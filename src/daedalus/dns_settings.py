"""Operator-only DNS audit resolver configuration."""
import ipaddress


def parse_audit_nameservers(value: str) -> tuple[str, ...]:
    entries = value.replace(",", " ").split()
    if len(entries) > 3:
        raise ValueError("DAEDALUS_AUDIT_DNS_NAMESERVERS accepts at most three IP addresses")
    result = []
    for entry in entries:
        if "%" in entry:
            raise ValueError("DNS audit resolvers must be unscoped IP addresses")
        try:
            address = ipaddress.ip_address(entry)
        except ValueError as exc:
            raise ValueError("DNS audit resolvers must be IP addresses") from exc
        if address.is_unspecified or address.is_multicast:
            raise ValueError("DNS audit resolvers must be unicast IP addresses")
        result.append(str(address))
    return tuple(dict.fromkeys(result))
