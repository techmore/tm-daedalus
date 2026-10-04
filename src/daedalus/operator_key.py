"""Explicit host operator provisioning; never exposed as an HTTP endpoint."""
from __future__ import annotations
import argparse
import json
import os
import secrets
from datetime import timedelta
from sqlalchemy import select
from daedalus.db import Base, engine, SessionLocal
from daedalus.models import Membership, Organization, User, UserAPIKey
from daedalus.server import audit, token_digest, utcnow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--output', required=True, help='New private file; refuses replacement')
    args = parser.parse_args()
    # Opening exclusively first prevents accidental issuance without a recoverable key.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        Base.metadata.create_all(engine)
        with SessionLocal() as db:
            org = db.scalar(select(Organization).where(Organization.domain == args.domain))
            if org is None or org.verification_status != 'verified':
                raise ValueError('An existing verified workspace is required')
            subject = 'service:codex-operator:' + org.domain
            user = db.scalar(select(User).where(User.google_subject == subject))
            if user is None:
                user = User(google_subject=subject, email='codex-operator@daedalus.invalid',
                            display_name='Codex operator', created_at=utcnow())
                db.add(user)
                db.flush()
            membership = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == org.id))
            if membership is None:
                db.add(Membership(user_id=user.id, organization_id=org.id, role='admin', status='approved', created_at=utcnow()))
            elif membership.status != 'approved' or membership.role != 'admin':
                raise ValueError('Existing operator membership requires explicit administrator review')
            token = 'dd_user_' + secrets.token_urlsafe(48)
            key = UserAPIKey(user_id=user.id, organization_id=org.id, name='Codex validation', token_hash=token_digest(token),
                             created_at=utcnow(), expires_at=utcnow()+timedelta(days=30))
            db.add(key)
            db.flush()
            audit(db, org.id, user.id, 'user_key.operator_provisioned', {'key_id':key.id, 'authorization':'Explicit owner request in Codex'})
            with os.fdopen(fd, 'w') as stream:
                fd = None
                json.dump({'token':token, 'key_id':key.id, 'organization_id':org.id, 'expires_at':key.expires_at.isoformat()+'Z'}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            db.commit()
        print('Codex operator key written to private file; token omitted.')
    except BaseException:
        if fd is not None:
            os.close(fd)
        os.unlink(args.output)
        raise


if __name__ == '__main__':
    main()
