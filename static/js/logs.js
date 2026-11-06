// The Logs screen (owner only): everything the server and the browsers have
// logged, one collapsible block per day, newest first. app.js calls
// Logs.init( me ) for admins; only the owner gets past the first line, and
// the server answers anyone else's call with a 404 regardless.
//
// The search box is passed to the server as typed. Free words match anywhere
// in an entry; key:value narrows (kind:ui status:5xx user:ana path:/api
// ip:10.0. level:error action:click), a comma means "or" (kind:auth,admin)
// and a leading minus excludes (-kind:request). The kind buttons under the
// box add a kind: term for you.
//
// The whole screen is data-no-track in index.html: reading the log would
// otherwise write to it.
const Logs = {
  kinds: [ "request" , "ui" , "auth" , "admin" , "error" , "system" ],
  selected: new Set(),
  searchDelayMs: 300,
  // The least time between reads while Live is on, however busy the server is.
  liveMs: 2000,
  searchTimer: null,
  liveOn: false,
  liveSource: null,
  liveTimer: null,
  liveLast: 0,
  // Which days are open, kept across a refresh; null until the first one,
  // which opens the newest day.
  openDays: null,

  async init( me ) {
    if ( !me.is_owner || !me.logs_enabled ) return;
    Dom.show( Dom.get( "logs-panel" ) , true );
    Dom.get( "logs-search-form" ).addEventListener( "submit" , ( event ) => {
      event.preventDefault();
      this.search();
    } );
    Dom.get( "logs-query" ).addEventListener( "input" , () => {
      window.clearTimeout( this.searchTimer );
      this.searchTimer = window.setTimeout( () => this.search() , this.searchDelayMs );
    } );
    Dom.get( "logs-live" ).addEventListener( "click" , () => this.toggleLive() );
    Dom.get( "logs-prune" ).addEventListener( "click" , () => this.onPrune() );
    window.addEventListener( "hashchange" , () => this.followScreen() );
    this.renderKinds();
    await this.refresh();
  },

  // A new search starts with the newest matching day open again.
  search() {
    this.openDays = null;
    return this.refresh();
  },

  query() {
    const typed = Dom.get( "logs-query" ).value.trim();
    const kinds = Array.from( this.selected );
    return [ typed , kinds.length ? "kind:" + kinds.join( "," ) : "" ].filter( Boolean ).join( " " );
  },

  renderKinds() {
    const holder = Dom.get( "logs-kinds" );
    Dom.clear( holder );
    this.kinds.forEach( ( kind ) => {
      const on = this.selected.has( kind );
      holder.appendChild( Dom.el( "button" , {
        class: "btn btn-sm " + ( on ? "btn-primary" : "btn-outline-secondary" ),
        text: I18n.get( "logs.kind_" + kind ) || kind,
        attrs: { type: "button" , "aria-pressed": String( on ) },
        on: { click: () => {
          if ( on ) this.selected.delete( kind );
          else this.selected.add( kind );
          this.renderKinds();
          this.search();
        } },
      } ) );
    } );
  },

  async refresh() {
    let listing;
    try {
      listing = await Api.logDays( this.query() );
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    this.renderSettings( listing );

    const container = Dom.get( "logs-days" );
    if ( this.openDays === null ) {
      this.openDays = new Set( listing.days.length ? [ listing.days[ 0 ].date ] : [] );
    } else {
      this.openDays = new Set( Dom.all( "details.log-day[open]" , container ).map( ( day ) => day.getAttribute( "data-date" ) ) );
    }

    Dom.clear( container );
    const empty = Dom.get( "logs-empty" );
    Dom.text( empty , I18n.get( this.query() ? "logs.no_matches" : "logs.empty" ) );
    Dom.show( empty , listing.days.length === 0 );
    listing.days.forEach( ( day ) => container.appendChild( this.dayBlock( day ) ) );
  },

  renderSettings( listing ) {
    const settings = listing.settings || {};
    let line = I18n.get( "logs.settings_line" )
      .replace( "{days}" , String( settings.retention_days ) )
      .replace( "{used}" , this.size( listing.total_bytes ) )
      .replace( "{max}" , String( settings.max_total_mb ) + " MB" )
      .replace( "{gzip}" , String( settings.compress_after_days ) );
    const stored = I18n.get( settings.encrypted ? "logs.encrypted" : "logs.not_encrypted" );
    if ( stored ) line += " · " + stored;
    if ( listing.dropped > 0 ) line += " · " + I18n.get( "logs.dropped" ).replace( "{count}" , String( listing.dropped ) );
    Dom.text( Dom.get( "logs-settings" ) , line );
  },

  // Days are UTC dates (the files are named by them); times in the rows are
  // shown in the viewer's own zone.
  dayLabel( date ) {
    return new Date( date + "T00:00:00Z" ).toLocaleDateString( undefined , {
      weekday: "short", year: "numeric", month: "short", day: "numeric", timeZone: "UTC",
    } );
  },

  today() {
    return new Date().toISOString().slice( 0 , 10 );
  },

  size( bytes ) {
    const value = Number( bytes ) || 0;
    if ( value < 1024 ) return value + " B";
    if ( value < 1024 * 1024 ) return ( value / 1024 ).toFixed( 1 ) + " KB";
    return ( value / 1024 / 1024 ).toFixed( 1 ) + " MB";
  },

  count( key , value ) {
    return I18n.get( key ).replace( "{count}" , Number( value || 0 ).toLocaleString() );
  },

  dayBlock( day ) {
    const meta = [
      day.matches !== undefined ? this.count( "logs.matches" , day.matches ) : this.count( "logs.entries" , day.entries ),
      this.size( day.bytes ),
    ];
    if ( day.compressed ) meta.push( I18n.get( "logs.compressed" ) );

    const summary = Dom.el( "summary" , { class: "log-day-summary" , children: [
      Dom.el( "span" , { class: "log-day-date" , text: this.dayLabel( day.date ) } ),
      Dom.el( "span" , { class: "log-day-meta" , text: meta.filter( Boolean ).join( " · " ) } ),
      day.errors > 0 ? Dom.badge( this.count( "logs.errors" , day.errors ) , "danger" ) : null,
    ].filter( Boolean ) } );

    // Download and delete sit inside the opened day rather than on the
    // summary line, where a click would also fold the day.
    const download = Dom.el( "a" , {
      class: "btn btn-sm btn-outline-secondary",
      text: I18n.get( "logs.download_button" ),
      attrs: { href: Api.logDownloadPath( day.date ) , download: "logs-" + day.date + ".jsonl" },
    } );
    const remove = day.date === this.today() ? null : Dom.el( "button" , {
      class: "btn btn-sm btn-outline-danger",
      text: I18n.get( "logs.delete_button" ),
      on: { click: () => this.onDeleteDay( day.date ) },
    } );
    const body = Dom.el( "div" , { class: "log-day-body" , children: [
      Dom.el( "div" , { class: "row-actions mb-2" , children: [ download , remove ].filter( Boolean ) } ),
    ] } );

    const block = Dom.el( "details" , { class: "log-day" , attrs: { "data-date": day.date } , children: [ summary , body ] } );
    block.addEventListener( "toggle" , () => {
      if ( block.open && !block._loaded ) {
        block._loaded = true;
        this.loadDay( block , body , day.date , null );
      }
    } );
    if ( this.openDays.has( day.date ) ) block.open = true;
    return block;
  },

  async loadDay( block , body , date , before ) {
    let page;
    try {
      page = await Api.logDay( date , this.query() , before );
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    let table = body.querySelector( "table" );
    if ( !table ) {
      table = Dom.el( "table" , { class: "table table-sm table-hover align-middle log-table" , children: [
        Dom.el( "thead" , { children: [ Dom.el( "tr" , { children: [
          Dom.el( "th" , { text: I18n.get( "logs.table_time" ) } ),
          Dom.el( "th" , { text: I18n.get( "logs.table_kind" ) } ),
          Dom.el( "th" , { text: I18n.get( "logs.table_user" ) } ),
          Dom.el( "th" , { text: I18n.get( "logs.table_what" ) } ),
          Dom.el( "th" , { text: I18n.get( "logs.table_ip" ) } ),
        ] } ) ] } ),
        Dom.el( "tbody" ),
      ] } );
      body.appendChild( Dom.el( "div" , { class: "table-responsive" , children: [ table ] } ) );
    }
    const rows = table.querySelector( "tbody" );
    page.entries.forEach( ( entry ) => this.appendEntry( rows , entry ) );

    const old = body.querySelector( ".log-more" );
    if ( old ) old.remove();
    if ( page.next !== null && page.next !== undefined ) {
      body.appendChild( Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary log-more",
        text: I18n.get( "logs.load_more" ),
        on: { click: () => this.loadDay( block , body , date , page.next ) },
      } ) );
    }
  },

  tone( entry ) {
    if ( entry.level === "error" || entry.kind === "error" ) return "danger";
    if ( entry.level === "warn" ) return "warning";
    return { request: "secondary" , ui: "info" , auth: "primary" , admin: "warning" , system: "dark" }[ entry.kind ] || "secondary";
  },

  who( entry ) {
    const actor = entry.actor || {};
    if ( !actor.user_id ) return I18n.get( "logs.anonymous" );
    const name = actor.name || "#" + actor.user_id;
    return actor.method === "api_key" ? name + " " + I18n.get( "logs.via_key" ) : name;
  },

  what( entry ) {
    if ( entry.request ) {
      const request = entry.request;
      return request.method + " " + request.path + " → " + request.status + " · " + Math.round( request.ms * 10 ) / 10 + " ms";
    }
    if ( entry.ui ) {
      const ui = entry.ui;
      return [ ui.action , ui.target , ui.screen ? "· " + ui.screen : "" ].filter( Boolean ).join( " " );
    }
    return entry.msg || "";
  },

  // A row, and under it the whole entry as JSON, shown by clicking the row.
  appendEntry( rows , entry ) {
    const detail = Dom.el( "tr" , { class: "log-detail" , attrs: { hidden: "" } , children: [
      Dom.el( "td" , { attrs: { colspan: "5" } , children: [
        Dom.el( "pre" , { class: "log-json" , text: JSON.stringify( entry , null , 2 ) } ),
      ] } ),
    ] } );
    const row = Dom.el( "tr" , {
      class: "log-row",
      attrs: { tabindex: "0" , "aria-expanded": "false" },
      children: [
        Dom.el( "td" , { class: "text-nowrap" , text: new Date( entry.ts ).toLocaleTimeString() } ),
        Dom.el( "td" , { children: [ Dom.badge( I18n.get( "logs.kind_" + entry.kind ) || entry.kind , this.tone( entry ) ) ] } ),
        Dom.el( "td" , { class: "text-nowrap" , text: this.who( entry ) } ),
        Dom.el( "td" , { class: "log-what" , text: this.what( entry ) } ),
        Dom.el( "td" , { class: "text-nowrap" , text: entry.ip || "" } ),
      ],
    } );
    const toggle = () => {
      detail.hidden = !detail.hidden;
      row.setAttribute( "aria-expanded" , String( !detail.hidden ) );
    };
    row.addEventListener( "click" , toggle );
    row.addEventListener( "keydown" , ( event ) => {
      if ( event.key === "Enter" || event.key === " " ) {
        event.preventDefault();
        toggle();
      }
    } );
    rows.appendChild( row );
    rows.appendChild( detail );
  },

  // Live: the server says when there is something new, and the list is read
  // again then, so a quiet server costs nothing. The stream only says "look
  // again": the entries come through the same read as everything else here,
  // with the search box applied.
  toggleLive() {
    this.setLive( !this.liveOn );
  },

  setLive( on ) {
    this.liveOn = on;
    const button = Dom.get( "logs-live" );
    button.setAttribute( "aria-pressed" , String( on ) );
    button.classList.toggle( "btn-primary" , on );
    button.classList.toggle( "btn-outline-secondary" , !on );
    this.followScreen();
  },

  // The stream is open only while this screen is showing, because each one
  // holds a connection, and a browser only gets a few per server.
  followScreen() {
    if ( this.liveOn && Nav.current() === "logs" ) {
      this.openLive();
    } else {
      this.closeLive();
    }
  },

  openLive() {
    if ( this.liveSource ) return;
    const source = new EventSource( Api.logStreamPath() );
    source.addEventListener( "changed" , () => this.onChanged() );
    // A dropped connection retries by itself. CLOSED means the server said no:
    // the session ended, or too many pages are watching.
    source.addEventListener( "error" , () => {
      if ( source.readyState !== EventSource.CLOSED ) return;
      this.setLive( false );
      App.showError( I18n.get( "logs.live_lost" ) );
    } );
    this.liveSource = source;
  },

  closeLive() {
    if ( this.liveSource ) this.liveSource.close();
    this.liveSource = null;
    window.clearTimeout( this.liveTimer );
    this.liveTimer = null;
  },

  // At most one read per liveMs, and the last change always gets one. It holds
  // off while an entry is expanded, so what is being read does not fold away
  // under the reader.
  onChanged() {
    if ( this.liveTimer ) return;
    const wait = Math.max( 0 , this.liveLast + this.liveMs - Date.now() );
    this.liveTimer = window.setTimeout( () => {
      this.liveTimer = null;
      this.liveLast = Date.now();
      if ( Dom.all( "#logs-days .log-detail:not([hidden])" ).length > 0 ) {
        this.onChanged();
        return;
      }
      this.refresh();
    } , wait );
  },

  async onPrune() {
    const question = I18n.get( "logs.prune_confirm" );
    if ( !( await Dom.confirm( question ) ) ) return;
    try {
      const result = await Api.pruneLogs();
      Dom.toast( I18n.get( "logs.pruned" )
        .replace( "{deleted}" , String( result.deleted ) )
        .replace( "{compressed}" , String( result.compressed ) ) , "ok" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  // No undo: the day's files are gone from disk.
  async onDeleteDay( date ) {
    const question = I18n.get( "logs.delete_confirm" ).replace( "{date}" , this.dayLabel( date ) );
    if ( !( await Dom.confirm( question ) ) ) return;
    try {
      await Api.deleteLogDay( date );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },
};
