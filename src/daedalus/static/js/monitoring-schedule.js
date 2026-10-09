/* Dated saved configuration, retained choices and read-only recovery. */
(function () {
  "use strict";
  window.DaedalusMonitoringSchedule = {create:function (options) {
    var type=options.type, host=document.getElementById(type+"-monitoring-details");if (!host) return null;
    var refresh=document.getElementById(type+"-schedule-refresh"), observed=document.getElementById(type+"-schedule-observed");
    var note=document.getElementById(type+"-schedule-read-note"), feedback=document.getElementById(type+"-schedule-feedback");
    var status=document.getElementById(type+"-schedule-status"), next=document.getElementById(type+"-schedule-next-run");
    var action=document.getElementById(type+"-action-schedule"), checkbox=document.querySelector('[data-schedule-enabled="'+type+'"]');
    var interval=document.querySelector('[data-schedule-interval="'+type+'"]'), button=document.querySelector('[data-save-schedule="'+type+'"]');
    var state={body:null,fresh:false,loading:false,saving:false,dirty:false,error:null,unconfirmed:false};
    var fields=["enabled","interval_hours","next_run_at","last_started_at","last_completed_at","last_run_status","updated_at"];
    function date(v) {return new Date(v).toLocaleString(undefined,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"});}
    function validDate(v) {return typeof v==="string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v));}
    function validate(body) {
      if (!body || body.organization_id!==Number(options.organizationId) || body.user_id!==Number(options.userId) || body.domain!==options.domain || body.check_type!==type ||
          typeof body.can_manage!=="boolean" || typeof body.enabled!=="boolean" || ![24,168].includes(body.interval_hours) || !validDate(body.observed_at) || Date.parse(body.observed_at)>Date.now()+60000 ||
          !/^[a-f0-9]{64}$/.test(body.state_reference||"") || body.updated_by!==null && typeof body.updated_by!=="string") throw new Error("The monitoring schedule could not be confirmed for this account and topic.");
      ["next_run_at","last_started_at","last_completed_at","updated_at"].forEach(function (key) {
        if (body[key]!==null && (!validDate(body[key]) || key!=="next_run_at" && Date.parse(body[key])>Date.parse(body.observed_at))) throw new Error("The saved schedule dates could not be confirmed.");
      });
      if (!body.enabled && body.next_run_at!==null || body.last_run_status!==null && typeof body.last_run_status!=="string") throw new Error("The saved schedule state is inconsistent.");
      return body;
    }
    function choice() {return checkbox && interval ? {enabled:checkbox.checked,interval_hours:Number(interval.value)} : null;}
    function sameChoice(a,b) {return a && b && a.enabled===b.enabled && a.interval_hours===b.interval_hours;}
    function canSave() {return state.fresh && !state.loading && !state.saving && state.body.can_manage && !!checkbox && !!interval;}
    function controls() {
      refresh.disabled=state.saving;refresh.setAttribute("aria-busy",String(state.loading));
      if (button) {button.disabled=!canSave();button.setAttribute("aria-busy",String(state.saving));}
      if (checkbox) checkbox.disabled=!state.fresh || state.loading || !state.body.can_manage;
      if (interval) interval.disabled=!checkbox || checkbox.disabled || !checkbox.checked;
      observed.textContent=state.body ? (state.fresh ? "Schedule read " : "Last observed ")+date(state.body.observed_at)+"." : "No saved schedule read yet.";
      note.hidden=!state.error && !state.dirty;
      note.textContent=state.error ? state.error+" "+(state.body ? "Saved configuration and your choices remain visible. " : "")+"Refresh schedule before saving again."
        : state.dirty ? "Your choices have not been saved. Saved configuration is shown above." : "";
      host.dataset.readStale=String(!state.fresh);
      if (action && state.body) {var presentation=options.present(state.body);action.textContent=(state.fresh ? "" : "Last observed: ")+presentation.label+" · "+presentation.detail;}
    }
    function restoreFocus(trigger) {
      if (document.activeElement && document.activeElement!==document.body && document.activeElement!==trigger) return;
      if (!host.contains(trigger) || trigger.disabled || trigger.hidden) refresh.focus({preventScroll:true});
      else if (document.activeElement!==trigger) trigger.focus({preventScroll:true});
    }
    function render() {
      var body=state.body, presentation=options.present(body);
      status.textContent=presentation.label;status.className="check-status";
      next.textContent=presentation.detail+(body.updated_at ? " Configuration saved "+date(body.updated_at)+" · "+(body.updated_by||"System or administrator unavailable")+"." : " Configuration save date unavailable.")+
        (body.last_completed_at ? " Last attempt "+date(body.last_completed_at)+(body.last_run_status ? " ("+body.last_run_status.replaceAll("_"," ")+")" : "")+"." : "");
      if (!state.dirty && checkbox && interval) {checkbox.checked=body.enabled;interval.value=String(body.interval_hours);}
    }
    async function request(method,payload,reference) {
      var controller=new AbortController(), rejectDeadline;
      var deadline=new Promise(function (_,reject) {rejectDeadline=reject;});
      var timer=window.setTimeout(function () {controller.abort();rejectDeadline(new Error("The monitoring schedule request timed out."));},20000);
      try {return await Promise.race([deadline,(async function () {
        var headers=new Headers();if (reference) headers.set("X-Daedalus-Schedule-State",reference);
        if (payload) headers.set("Content-Type","application/json");
        var response=await options.fetch("/api/external-checks/"+type+"/schedule",{method:method,headers:headers,credentials:"same-origin",cache:"no-store",signal:controller.signal,body:payload ? JSON.stringify(payload) : undefined});
        var body;try {body=await response.json();} catch (_) {body=null;}
        if (!response.ok) throw new Error(body && typeof body.detail==="string" ? body.detail : "The schedule request could not be confirmed.");
        return validate(body);
      })()]);} finally {window.clearTimeout(timer);}
    }
    async function load() {
      if (state.loading || state.saving) return false;
      var trigger=document.activeElement, restore=host.contains(trigger);state.loading=true;state.error=null;controls();
      try {
        state.body=await request("GET");state.fresh=true;if (state.dirty && sameChoice(choice(),state.body)) state.dirty=false;render();
        if (state.unconfirmed) {feedback.textContent="Schedule status refreshed "+date(state.body.observed_at)+". "+options.present(state.body).label+". "+(state.dirty ? "Review your retained choices before saving another change." : "The saved configuration matches the displayed choices.");state.unconfirmed=false;}
        return true;
      } catch (error) {state.fresh=false;state.error=error.message;return false;}
      finally {state.loading=false;controls();if (restore) restoreFocus(trigger);}
    }
    async function save() {
      if (!canSave()) return false;
      var submitted=choice(), trigger=document.activeElement, restore=host.contains(trigger), reference=state.body.state_reference;
      if (!submitted || ![24,168].includes(submitted.interval_hours)) return false;
      state.saving=true;state.error=null;feedback.textContent="Saving monitoring configuration…";controls();var saved=false;
      try {
        var body=await request("PUT",submitted,reference);
        if (typeof body.changed!=="boolean" || !sameChoice(body,submitted) || body.changed && body.state_reference===reference) throw new Error("The schedule save response is incomplete.");
        state.body=body;state.fresh=true;state.unconfirmed=false;
        if (sameChoice(choice(),submitted)) state.dirty=false;
        render();feedback.textContent=(body.changed ? "Schedule saved " : "Existing schedule retained ")+date(body.updated_at||body.observed_at)+". "+options.present(body).label+". "+(body.changed ? "" : "The collection time was not reset. ")+(state.dirty ? "Your newer choices remain unsaved." : "");saved=true;
      } catch (error) {state.fresh=false;state.error=error.message;state.unconfirmed=true;feedback.textContent="The schedule save was not confirmed. "+error.message+" Refresh schedule to check what was saved before trying again.";}
      finally {state.saving=false;controls();if (restore) restoreFocus(trigger);}
      if (saved) {try {await options.onSaved();} catch (_) {}}
      return saved;
    }
    function observe(snapshot) {
      if (state.loading || state.saving) return;
      if (!state.body || state.fresh && snapshot && fields.some(function (key) {return snapshot[key]!==state.body[key];})) load();
    }
    async function enable(cadence, reviewed) {
      if (state.dirty) throw new Error("Review your unsaved monitoring choices in this topic.");
      if (!await load() || !state.body.can_manage || !checkbox || !interval) throw new Error("Refresh the monitoring schedule before enabling checks.");
      if (state.body.enabled && state.body.interval_hours===cadence) return true;
      if (state.body.enabled || state.body.interval_hours!==cadence || state.body.updated_at!==reviewed.updated_at) throw new Error("The monitoring configuration changed. Review its current saved status.");
      checkbox.checked=true;interval.value=String(cadence);state.dirty=true;
      if (!await save()) throw new Error("The save was not confirmed. Review monitoring schedule to check the saved status.");
      return true;
    }
    refresh.addEventListener("click",load);
    [checkbox,interval].forEach(function (field) {if (field) field.addEventListener("change",function () {state.dirty=true;controls();});});
    if (button) button.addEventListener("click",save);
    controls();return {state:state,load:load,save:save,observe:observe,enable:enable};
  }};
})();
