// What changed while this tab was in the background.
//
// A tab can sit open for days, and everything /api/me said when the page loaded
// goes stale in that time. So coming back to it asks again, and acts on the
// answer: the session may have ended, maintenance may have started or finished,
// and the server may have been upgraded under a page that is still the old one.
//
// Only on coming back, not on a timer: a tab nobody is looking at has no reason
// to call the server, and calling would count as use and keep its session alive.
const Fresh = {
  // No more often than this, so flicking between tabs is not a request each time.
  everyMs: 5 * 60 * 1000,
  asked: 0,
  version: "",

  init( me ) {
    this.asked = Date.now();
    this.version = me.version;
    document.addEventListener( "visibilitychange" , () => {
      if ( !document.hidden ) this.check();
    } );
  },

  async check() {
    if ( Date.now() - this.asked < this.everyMs ) return;
    this.asked = Date.now();
    let me;
    try {
      me = await Api.me();
    } catch ( error ) {
      // The server being away is news only once someone tries to use it.
      return;
    }
    if ( !me.authenticated ) {
      Api.sessionEnded();
      return;
    }
    App.showMaintenance( me );
    App.showAnnouncement( me );
    this.noticeVersion( me.version );
  },

  // dev is what a build with no version stamped says, which is every build of
  // one being worked on, so a change to or from it means nothing. Told once:
  // someone who ignores the toast has seen it.
  noticeVersion( version ) {
    if ( version === this.version || version === "dev" || this.version === "dev" ) return;
    this.version = version;
    Dom.toast( I18n.get( "fresh.new_version" ) , "ok" , {
      text: I18n.get( "fresh.reload" ),
      run: () => window.location.reload(),
    } );
  },
};
