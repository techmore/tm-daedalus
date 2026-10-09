/* Explicit customer creation, per-domain outcomes and saved-read recovery. */
(function () {
  "use strict";
  window.DaedalusCustomerCreation = {create:function (options) {
    var form=document.getElementById("create-workspace-form"),feedback=document.getElementById("customer-create-feedback");
    if (!form || !feedback) return null;
    var result=document.getElementById("customer-create-result"),rows=document.getElementById("customer-create-rows");
    var title=document.getElementById("customer-create-result-title"),observed=document.getElementById("customer-create-observed");
    var submit=form.querySelector('button[type="submit"]'),entries=[],state={busy:false,body:null};
    function draft() {var data=new FormData(form);return {name:String(data.get("name")||""),domains:String(data.get("domains")||""),onboarding:data.get("onboarding")==="on",reason:String(data.get("onboarding_reason")||"Vendor transition: complimentary onboarding")};}
    function validDate(value) {return typeof value==="string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));}
    function dateLabel(value) {return new Date(value).toLocaleString(undefined,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"});}
    function validate(body,payload) {
      if (!body || body.user_id!==Number(options.userId) || body.customer!==payload.name || !validDate(body.observed_at) || Date.parse(body.observed_at)>Date.now()+60000 ||
          !Number.isSafeInteger(body.created) || body.created<0 || !Array.isArray(body.results) || !body.results.length || body.results.length>payload.domains.length) throw new Error("Customer creation could not be confirmed.");
      var domains=new Set(),ids=new Set(),created=0;
      body.results.forEach(function (item) {
        if (!item || !["created","exists","invalid"].includes(item.status)) throw new Error("Customer creation results are incomplete.");
        if (item.status==="invalid") {
          if (typeof (item.input||item.domain)!=="string" || !(item.input||item.domain) || typeof item.detail!=="string") throw new Error("An invalid-domain result could not be confirmed.");
        } else {
          if (typeof item.domain!=="string" || !item.domain || domains.has(item.domain)) throw new Error("Customer domain results could not be confirmed.");
          domains.add(item.domain);
        }
        if (item.status==="created") {
          if (!Number.isSafeInteger(item.organization_id) || item.organization_id<=0 || ids.has(item.organization_id) || typeof item.name!=="string" || !item.name || !validDate(item.created_at) || !validDate(item.probation_expires_at) || Date.parse(item.created_at)>Date.parse(body.observed_at)+60000 || Date.parse(item.probation_expires_at)<=Date.parse(item.created_at)) throw new Error("A created workspace could not be confirmed.");
          ids.add(item.organization_id);created++;
        }
      });
      if (created!==body.created) throw new Error("The created workspace count could not be confirmed.");
      return body;
    }
    function workspace(item) {
      var review=options.workspaceReview();
      return review && review.state.body && review.state.body.workspaces.find(function (w) {return w.domain===item.domain && w.status==="approved";});
    }
    function updateControls() {
      if (submit) {submit.disabled=state.busy;submit.setAttribute("aria-busy",String(state.busy));}
      entries.forEach(function (entry) {
        if (!entry.button) return;
        var existing=workspace(entry.item),id=entry.item.status==="created" ? entry.item.organization_id : existing && existing.id;
        entry.id=id;entry.button.dataset.workspaceReviewOpen=id ? String(id) : "";
        entry.button.textContent=id ? "Open workspace" : "Request access";
        entry.button.setAttribute("aria-label",entry.button.textContent+": "+entry.item.domain);
        var review=options.workspaceReview();
        entry.button.setAttribute("aria-disabled",String(state.busy || options.selectionBusy() || Boolean(id && (!review || !review.canSelect(id)))));
      });
    }
    function render(body) {
      var active=document.activeElement,wasFocused=rows.contains(active);rows.replaceChildren();entries=[];
      body.results.forEach(function (item) {
        var row=document.createElement("div");row.className="workspace-request-row";
        var detail=document.createElement("div"),name=document.createElement("strong"),status=document.createElement("small");
        name.textContent=item.domain||item.input;
        status.textContent=item.status==="created" ? "Workspace added. Domain ownership is awaiting verification." : item.status==="exists" ? "Already has a workspace; access depends on its administrator." : item.detail;
        detail.append(name,status);
        if (item.status==="created") {var when=document.createElement("small");when.textContent="Added "+dateLabel(item.created_at)+". Ownership review deadline "+dateLabel(item.probation_expires_at)+".";detail.append(when);}
        row.append(detail);var entry={item:item,button:null,id:null};
        if (item.status!=="invalid") {
          entry.button=document.createElement("button");entry.button.type="button";entry.button.className="button button-small button-quiet";
          entry.button.addEventListener("click",function (event) {
            event.stopPropagation();if (state.busy || options.selectionBusy()) return;
            if (entry.id) {var review=options.workspaceReview();if (review && review.canSelect(entry.id)) options.select(entry.id,entry.button);}
            else {var input=document.querySelector('#request-access-form input[name="domain"]');if (input) {input.value=item.domain;input.focus();}}
          });row.append(entry.button);
        }
        entries.push(entry);rows.append(row);
      });
      title.textContent=body.customer+" · creation results";observed.textContent=body.created+" workspace"+(body.created===1 ? "" : "s")+" added. Recorded "+dateLabel(body.observed_at)+".";
      result.classList.remove("hidden");result.hidden=false;
      if (wasFocused) document.getElementById("dialog-workspace-refresh").focus();
      updateControls();
    }
    form.addEventListener("submit",async function (event) {
      event.preventDefault();if (state.busy) return;
      var values=draft(),signature=JSON.stringify(values),payload={name:values.name.trim(),domains:values.domains.split(/[\s,;]+/).filter(Boolean),onboarding:values.onboarding,onboarding_reason:values.reason,select_created_workspace:false};
      if (payload.name.length<2 || !payload.domains.length || payload.domains.length>20) {feedback.textContent="Enter a customer name and between 1 and 20 domains. Duplicate domains create one workspace.";return;}
      state.busy=true;updateControls();feedback.textContent="Adding customer workspaces…";
      var controller=new AbortController(),timer=window.setTimeout(function () {controller.abort();},20000),saved=false;
      try {
        var response=await options.fetch("/api/customers",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload),signal:controller.signal});
        var body;try {body=await response.json();} catch (_) {body=null;}
        if (controller.signal.aborted) throw new Error("Customer creation timed out.");
        if (!response.ok) throw new Error(body && typeof body.detail==="string" ? body.detail : "Customer creation could not be confirmed. Check the name, domains and approval reason.");
        validate(body,payload);saved=true;state.body=body;render(body);
        feedback.textContent=body.created ? "Customer workspaces saved. Review each domain below; opening a workspace is a separate action." : "No new workspaces were added. Review each domain below.";
        if (body.created && body.results.every(function (item) {return item.status==="created";}) && JSON.stringify(draft())===signature) form.reset();
      } catch (error) {
        feedback.textContent=(controller.signal.aborted ? "Customer creation timed out." : error.message)+" Your entered details are retained. Use Refresh workspaces to check what was saved before submitting again.";
      } finally {window.clearTimeout(timer);state.busy=false;updateControls();}
      // A saved creation remains confirmed even if its independent list read fails.
      if (saved) {try {await options.afterSave();} catch (_) {}updateControls();}
    });
    return {state:state,updateControls:updateControls};
  }};
})();
