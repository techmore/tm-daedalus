(function () {
  "use strict";
  var dialog = document.getElementById("onboarding-review-dialog");
  if (!dialog) return;
  var reminder = document.getElementById("onboarding-review-reminder");
  var reminderStatus = document.getElementById("onboarding-review-status");
  var reviewButton = document.getElementById("onboarding-review-open");
  var customerList = document.getElementById("onboarding-customers");
  var dueList = document.getElementById("onboarding-due-customers");
  var dueCount = null;
  var loading = null;

  function setText(target, value) {
    if (target && target.textContent !== value) target.textContent = value;
  }

  function updateReminder(count, refreshFailed) {
    dueCount = count;
    if (!reminder) return;
    reminder.classList.toggle("hidden", !count && !refreshFailed);
    if (count) {
      var message = count === 1 ? "1 customer approval needs review." : count + " customer approvals need review.";
      if (refreshFailed) message += " Could not refresh; this is the last loaded count.";
      setText(reminderStatus, message);
    } else if (refreshFailed) {
      setText(reminderStatus, count === null ? "Customer access review status is unavailable. Open the review to retry." : "No approvals were due at the last refresh. Current review status is unavailable.");
    }
  }

  function render(target, customers) {
    if (!target) return;
    var fingerprint = JSON.stringify(customers);
    if (target.dataset.fingerprint === fingerprint) return;
    var active = document.activeElement;
    var focusedRow = Array.from(target.children).find(function (row) { return row.contains(active); });
    var focusedCustomer = focusedRow && focusedRow.dataset.customerId;
    var focusedControl = active && active.dataset.onboardingControl;
    target.dataset.fingerprint = fingerprint;
    target.replaceChildren();
    if (!customers.length) {
      target.textContent = "No customers need review.";
      return;
    }
    customers.forEach(function (customer) {
      var grant = customer.onboarding;
      var row = document.createElement("form");
      row.className = "onboarding-customer";
      row.dataset.customerId = String(customer.id);
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
      reason.dataset.onboardingControl = "reason";
      label.append(reason);
      row.append(name, state, label);
      var actions = document.createElement("div");
      actions.className = "onboarding-actions";
      if (!grant || grant.status === "ended" || grant.review_required) {
        var approve = document.createElement("button");
        approve.type = "submit";
        approve.className = "button button-primary";
        approve.value = "approve";
        approve.dataset.onboardingControl = "approve";
        approve.textContent = grant && grant.review_required ? "Reapprove for 30 days" : "Approve onboarding for 30 days";
        actions.append(approve);
      }
      if (grant && grant.status === "onboarding") {
        var end = document.createElement("button");
        end.type = "submit";
        end.className = "button button-quiet";
        end.value = "end";
        end.dataset.onboardingControl = "end";
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
          if (await load(true) !== true) {
            feedback.textContent = "Decision saved. Customer access could not refresh. Refresh the list before another decision.";
            var refresh = document.createElement("button");
            refresh.type = "button";
            refresh.className = "button button-quiet";
            refresh.textContent = "Refresh customer access";
            refresh.addEventListener("click", async function () {
              refresh.disabled = true;
              if (await load(true) !== true) refresh.disabled = false;
            });
            feedback.append(refresh);
          }
          window.dispatchEvent(new Event("daedalus-onboarding-changed"));
        } catch (error) {
          feedback.textContent = error.message;
          buttons.forEach(function (button) { button.disabled = false; });
        }
      });
      target.append(row);
    });
    if (focusedCustomer) {
      var replacement = Array.from(target.children).find(function (row) { return row.dataset.customerId === focusedCustomer; });
      if (replacement) {
        var controls = Array.from(replacement.querySelectorAll("input, button"));
        var control = controls.find(function (item) { return item.dataset.onboardingControl === focusedControl; }) || controls[0];
        if (control) control.focus();
      } else if (dialog.open) document.getElementById("onboarding-review-later").focus();
    }
  }

  function load(force) {
    if (loading) return force === true ? loading.then(function () { return load(true); }) : loading;
    loading = fetchCustomers(force).finally(function () { loading = null; });
    return loading;
  }

  async function fetchCustomers(force) {
    try {
      var response = await fetch("/api/admin/onboarding", {credentials: "same-origin"});
      if (!response.ok) throw new Error("Customer onboarding could not be loaded. Refresh after signing in.");
      var body = await response.json();
      var due = body.customers.filter(function (customer) { return customer.onboarding && customer.onboarding.review_required; });
      updateReminder(due.length, false);
      setText(document.getElementById("onboarding-feedback"), "");
      setText(document.getElementById("onboarding-review-feedback"), "");
      // Background refreshes must not replace a focused form or its observed
      // decision version. Unchanged lists retain drafts even after focus moves.
      if (force === true || !customerList.contains(document.activeElement)) {
        render(customerList, body.customers);
      }
      if (force === true || !dueList.contains(document.activeElement)) render(dueList, due);
      if (!due.length && dialog.open && (force === true || !dueList.contains(document.activeElement))) dialog.close();
      return true;
    } catch (error) {
      updateReminder(dueCount, true);
      setText(document.getElementById("onboarding-feedback"), error.message);
      setText(document.getElementById("onboarding-review-feedback"), error.message);
      return false;
    }
  }
  if (reviewButton) reviewButton.addEventListener("click", function () {
    if (!dialog.open && !document.querySelector("dialog[open]")) dialog.showModal();
    load();
  });
  document.getElementById("onboarding-review-later").addEventListener("click", function () {
    dialog.close();
  });
  dialog.addEventListener("close", function () {
    var destination = reviewButton && !reminder.classList.contains("hidden") ? reviewButton : document.querySelector("[data-open-workspace-dialog]");
    if (destination) destination.focus();
  });
  document.querySelectorAll("[data-open-workspace-dialog]").forEach(function (button) { button.addEventListener("click", load); });
  window.daedalusOnboarding = {load: load};
  load();
  window.setInterval(function () { if (!document.hidden) load(); }, 60000);
}());
