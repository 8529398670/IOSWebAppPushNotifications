// The Jobs screen (owner only): what runs in the background and how its last
// run went. app.js calls Jobs.init( me ) for admins; only the owner gets past
// the first line, and the server answers anyone else with a 404 regardless.
//
// The rows come from the server in full, so a job an app adds shows up here
// with no change to this file. A job gets a friendlier name from
// jobs.job_<name> in language.yaml if it has one, and shows its own otherwise.
const Jobs = {
  // How often to look again while something is running here. A run outlives
  // the request that started it, so the page has to come back for the result.
  refreshMs: 3000,
  timer: null,

  async init( me ) {
    if ( !me.is_owner ) return;
    Dom.show( Dom.get( "jobs-panel" ) , true );
    window.addEventListener( "hashchange" , () => {
      if ( Nav.current() === "jobs" ) this.refresh();
    } );
    await this.refresh();
  },

  label( job ) {
    return I18n.get( "jobs.job_" + job.name.replace( /-/g , "_" ) ) || job.name;
  },

  status( job ) {
    if ( job.running ) return Dom.badge( I18n.get( "jobs.status_running" ) , "primary" );
    if ( job.interrupted ) return Dom.badge( I18n.get( "jobs.status_interrupted" ) , "warning" );
    if ( job.last_ok === undefined ) return Dom.badge( I18n.get( "jobs.status_never" ) , "secondary" );
    return job.last_ok
      ? Dom.badge( I18n.get( "jobs.status_ok" ) , "success" )
      : Dom.badge( I18n.get( "jobs.status_failed" ) , "danger" );
  },

  runButton( job ) {
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-secondary text-nowrap",
      text: I18n.get( "jobs.run_button" ),
      attrs: job.running ? { disabled: "disabled" } : {},
      on: { click: async () => {
        try {
          await Api.runJob( job.name );
          await this.refresh();
        } catch ( error ) { App.showError( error.message ); }
      } },
    } );
  },

  async refresh() {
    window.clearTimeout( this.timer );
    this.timer = null;
    let payload;
    try {
      payload = await Api.jobs();
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    const body = Dom.get( "jobs-table" ).querySelector( "tbody" );
    Dom.clear( body );
    payload.jobs.forEach( ( job ) => {
      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { text: this.label( job ) } ),
        Dom.el( "td" , { children: [ this.status( job ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( job.last_finished || job.last_started , I18n.get( "jobs.never" ) ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( job.next_due , I18n.get( "jobs.never" ) ) ] } ),
        Dom.el( "td" , { class: "small" , text: job.last_error || job.last_note || "" } ),
        Dom.el( "td" , { children: [ this.runButton( job ) ] } ),
      ] } ) );
    } );
    if ( payload.jobs.length === 0 ) Pager.empty( Dom.get( "jobs-table" ) );
    const running = payload.jobs.some( function ( job ) { return job.running; } );
    if ( running && Nav.current() === "jobs" ) {
      this.timer = window.setTimeout( () => this.refresh() , this.refreshMs );
    }
  },
};
