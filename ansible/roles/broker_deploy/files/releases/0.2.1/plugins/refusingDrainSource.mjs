// dist/plugins/refusingDrainSource.js
var DRAIN_REFUSAL = "mail is collected from the mail queue directly; nothing is handed over here";
var drainSource = {
  real: true,
  poll() {
    return Promise.reject(new Error(DRAIN_REFUSAL));
  }
};
var refusingDrainSource_default = drainSource;
export {
  DRAIN_REFUSAL,
  refusingDrainSource_default as default
};
