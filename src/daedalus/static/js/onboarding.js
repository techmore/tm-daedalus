(function () {
  "use strict";
  var dialog = document.getElementById("onboarding-review-dialog");
  if (!dialog) return;
  var dismissed = "";
  var loading = false;

  function render(target, customers) {
    target.replaceChildren();
    if (!customers.length) {
      target.textContent = "No customers need review.";
      return;
    }
    customers.forEach(function (customer) {
      var grant = customer.onboarding;
      var row = document.createElement("form");
      row.className = "onboarding-customer";
      var name = document.createElement("strong");
      name.textContent = customer.name + " · " + customer.domain;
      var state = document.createElement("p");
      state.textContent = !grant || grant.status === "ended" ? "Onboarding inactive" :
        "Complimentary onboarding · " + (grant.review_required ? "Reapproval required since " : "Review due ") + new Date(grant.review_due_at).toLocaleString();
      var label = document.createElement("label");
      label.textContent = "Reason for this decision";
      var reason = document.createElement("input");
      reason.required = true;
      reason.minLength = 8;
      reason.maxLength = 500;
      reason.value = grant ? grant.reason : "Vendor transition: complimentary onboarding";
      label.append(reason);
      row.append(name, state, label);
      var actions = document.createElement("div");
      actions.className = "onboarding-actions";
      if (!grant || grant.status === "ended" || grant.review_required) {
        var approve = document.createElement("button");
        approve.type = "submit";
        approve.className = "button button-primary";
        approve.value = "approve";
        approve.textContent = grant && grant.review_required ? "Reapprove for 30 days" : "Approve onboarding for 30 days";
        actions.append(approve);
      }
      if (grant && grant.status === "onboarding") {
        var end = document.createElement("button");
        end.type = "submit";
        end.className = "button button-quiet";
        end.value = "end";
        end.textContent = "End onboarding";
        actions.append(end);
      }
      var feedback = document.createElement("p");
      feedback.setAttribute("aria-live", "polite");
      row.append(actions, feedback);
      row.addEventListener("submit", async function (event) {
        event.preventDefault();
        var buttons = row.querySelectorAll("button");
        buttons.forEach(function (button) { button.disabled = true; });
        feedback.textContent = "Saving decision…";
        try {
          var response = await fetch("/api/admin/onboarding/" + customer.id, {
            method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/json"},
            body: JSON.stringify({version: grant ? grant.version : 0, action: event.submitter ? event.submitter.value : "approve", reason: reason.value})
          });
          var body = await response.json();
          if (!response.ok) throw new Error(body.detail || "Could not save the decision");
          await load(true);
          window.dispatchEvent(new Event("daedalus-onboarding-changed"));
        } catch (error) {
          feedback.textContent = error.message;
          buttons.forEach(function (button) { button.disabled = false; });
        }
      });
      target.append(row);
    });
  }

  async function load(force) {
    if (loading) return;
    loading = true;
    try {
      var response = await fetch("/api/admin/onboarding", {credentials: "same-origin"});
      if (!response.ok) throw new Error("Customer onboarding could not be loaded. Refresh after signing in.");
      var body = await response.json();
      var due = body.customers.filter(function (customer) { return customer.onboarding && customer.onboarding.review_required; });
      var fingerprint = due.map(function (customer) { return customer.id + ":" + customer.onboarding.version; }).sort().join(",");
      // Preserve edits while a form is in use; a manual save always reloads after focus leaves the form.
      if (force === true || !document.getElementById("onboarding-customers").contains(document.activeElement)) {
        render(document.getElementById("onboarding-customers"), body.customers);
      }
      if (force === true || !dialog.open || !dialog.contains(document.activeElement)) render(document.getElementById("onboarding-due-customers"), due);
      if (!due.length && dialog.open) dialog.close();
      if (due.length && fingerprint !== dismissed && !dialog.open && !document.querySelector("dialog[open]")) dialog.showModal();
      dialog.dataset.fingerprint = fingerprint;
    } catch (error) {
      document.getElementById("onboarding-feedback").textContent = error.message;
    } finally {
      loading = false;
    }
  }
  document.getElementById("onboarding-review-later").addEventListener("click", function () {
    dismissed = dialog.dataset.fingerprint;
    dialog.close();
  });
  dialog.addEventListener("cancel", function () { dismissed = dialog.dataset.fingerprint; });
  document.querySelectorAll("[data-open-workspace-dialog]").forEach(function (button) { button.addEventListener("click", load); });
  window.daedalusOnboarding = {load: load};
  load();
  window.setInterval(function () { if (!document.hidden) load(); }, 60000);
}());
