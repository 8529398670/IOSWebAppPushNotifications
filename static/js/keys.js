// The API keys screen: what has standing, non-browser access to this app.
//
// Its own file with its own init(), per the convention in the frontend
// reference -- app.js stays the account/admin screen rather than growing a
// second one. app.js calls Keys.init( me ) once it knows who is signed in.
//
// Two sections, and the difference matters: "my keys" is for every signed-in
// user, and the all-keys table is the admin's answer to "who and what can get
// in". A key created here carries a role from the same set users have, and can
// never be given more than the account that owns it.
//
// An admin can also make a key that acts as someone else, on the all-keys
// screen. The picker only offers the accounts the server would allow, and the
// key says who made it in both tables, so the person it acts as can see that.
const Keys = {
  me: null,
  // The accounts in the picker, by id, for the role choice to look at.
  targets: new Map(),

  async init( me ) {
    this.me = me;
    // The server can switch the whole feature off (auth.api_keys: false in config.yaml). When it
    // has, the endpoints are gone, so showing the panel would only produce a
    // form that 404s.
    if ( me.api_keys_enabled === false ) return;

    Dom.show( Dom.get( "api-keys-panel" ) , true );
    // Only an admin is offered the role choice. A non-admin has exactly one
    // option, and an "admin" entry the server would refuse is worse than no
    // choice at all.
    Dom.show( Dom.get( "key-role-field" ) , me.role === "admin" );
    Dom.onSubmit( Dom.get( "create-key-form" ) , this.onCreate.bind( this ) );
    Dom.get( "copy-key-button" ).addEventListener( "click" , this.onCopy.bind( this ) );
    await this.refresh();

    if ( me.role !== "admin" ) return;
    Dom.show( Dom.get( "admin-keys-panel" ) , true );
    Dom.onSubmit( Dom.get( "create-user-key-form" ) , this.onCreateFor.bind( this ) );
    Dom.get( "user-key-user" ).addEventListener( "change" , this.onTargetChange.bind( this ) );
    Dom.get( "copy-user-key-button" ).addEventListener( "click" , () => Dom.copy( Dom.get( "user-key-secret-value" ) ) );
    await this.refreshAll();
  },

  // A key is shown once, on creation, and is unrecoverable afterwards -- the
  // server stores only a hash. Saying so next to the value is the whole reason
  // this box exists rather than a toast that disappears.
  showSecret( credential ) {
    Dom.text( Dom.get( "key-secret-value" ) , credential );
    Dom.show( Dom.get( "key-secret-box" ) , true );
  },

  async onCopy() {
    await Dom.copy( Dom.get( "key-secret-value" ) );
  },

  async onCreate( event ) {
    event.preventDefault();
    const name = Dom.get( "key-name" ).value.trim();
    const role = this.me.role === "admin" ? Dom.get( "key-role" ).value : "user";

    // An empty field means "no opinion", which the server reads as its
    // configured default. Sending 0 instead would ask for a key that never
    // expires, which is a different thing and has to be typed on purpose.
    const rawDays = Dom.get( "key-days" ).value.trim();
    const expiresInDays = rawDays === "" ? null : Number( rawDays );

    try {
      const created = await Api.createKey( name , role , expiresInDays );
      this.showSecret( created.credential );
      Dom.get( "key-name" ).value = "";
      await this.refresh();
      if ( this.me.role === "admin" ) await this.refreshAll();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  // Who an admin may make a key for: the server's rules, so nobody is offered
  // a choice it would refuse. Admin accounts are the owner's to choose, nobody
  // picks the owner, and a disabled account cannot hold a new key.
  mayMintFor( user ) {
    if ( user.id === this.me.id || user.owner || user.disabled ) return false;
    return user.role !== "admin" || this.me.is_owner;
  },

  // Every page of accounts, since a picker missing someone looks like a bug.
  async loadTargets() {
    const users = [];
    let offset = 0;
    while ( offset !== null ) {
      const page = await Api.listUsers( offset );
      users.push( ...page.users );
      offset = page.next;
    }
    const picker = Dom.get( "user-key-user" );
    const chosen = picker.value;
    this.targets = new Map();
    picker.replaceChildren();
    for ( const user of users ) {
      if ( !this.mayMintFor( user ) ) continue;
      this.targets.set( String( user.id ) , user );
      picker.appendChild( Dom.el( "option" , { text: user.display_name , attrs: { value: String( user.id ) } } ) );
    }
    if ( this.targets.has( chosen ) ) picker.value = chosen;
    this.onTargetChange();
  },

  // An admin role is only a real choice for an admin account.
  onTargetChange() {
    const target = this.targets.get( Dom.get( "user-key-user" ).value );
    const role = Dom.get( "user-key-role" );
    const admin = target !== undefined && target.role === "admin";
    role.querySelector( "option[value=admin]" ).disabled = !admin;
    if ( !admin ) role.value = "user";
  },

  async onCreateFor( event ) {
    event.preventDefault();
    const target = this.targets.get( Dom.get( "user-key-user" ).value );
    if ( target === undefined ) return;
    const rawDays = Dom.get( "user-key-days" ).value.trim();
    const expiresInDays = rawDays === "" ? null : Number( rawDays );
    try {
      const created = await Api.createKeyFor( target.id , Dom.get( "user-key-name" ).value.trim() , Dom.get( "user-key-role" ).value , expiresInDays );
      Dom.text( Dom.get( "user-key-secret-value" ) , created.credential );
      Dom.show( Dom.get( "user-key-secret-box" ) , true );
      Dom.get( "user-key-name" ).value = "";
      await this.refreshAll();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  // The name cell: the name edits in place, and a key someone else made says so
  // under it. rename is the endpoint, as in revokeButton; refreshOther is the
  // table this one is not. This table keeps its row, so the name being edited
  // does not vanish from under the keyboard; the other shows the same key.
  nameCell( key , rename , refreshOther ) {
    const cell = Dom.el( "td" , { children: [ Dom.editable( key.name , {
      label: I18n.get( "api_keys.table_name" ),
      maxLength: 80,
      save: async function ( name ) {
        const previous = key.name;
        await rename( key.id , name , previous );
        key.name = name;
        Undo.record( {
          label: I18n.get( "undo.rename_key" ),
          toast: true,
          undo: async () => { await rename( key.id , previous , name ); await Keys.refreshBoth(); },
          redo: async () => { await rename( key.id , name , previous ); await Keys.refreshBoth(); },
        } );
        refreshOther().catch( ( error ) => App.showError( error.message ) );
      },
    } ) ] } );
    if ( key.created_by ) {
      cell.appendChild( Dom.el( "div" , {
        class: "small text-body-secondary",
        text: I18n.get( "api_keys.created_by" ).replace( "{name}" , key.created_by_name || ( "#" + key.created_by ) ),
      } ) );
    }
    return cell;
  },

  statusText( key ) {
    if ( key.revoked ) return I18n.get( "api_keys.status_revoked" );
    if ( key.expired ) return I18n.get( "api_keys.status_expired" );
    return I18n.get( "api_keys.status_active" );
  },

  statusBadge( key ) {
    const tone = key.revoked ? "secondary" : key.expired ? "warning" : "success";
    return Dom.badge( Keys.statusText( key ) , tone );
  },

  // revokeButton and deleteButton are shared by both tables: the only
  // difference is which endpoint acts on the key, so that is the parameter.
  // Revoking keeps the row, marked dead; deleting takes it off the list.
  // Revoke is only offered on a live key, delete on every key.
  //
  // Delete is undoable and revoke is not. The server only marks a deleted
  // key, and can put it back for a few minutes, so delete asks nothing and
  // offers Undo instead. Revoking says "stop trusting this" -- the leaked-key
  // button -- and an undo would quietly trust it again, so it asks first and
  // stays done.
  revokeButton( key , revoke ) {
    if ( !key.live ) return null;
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-danger",
      text: I18n.get( "api_keys.revoke_button" ),
      on: { click: async function () {
        // An empty confirm message means "do not ask", following the same
        // language.yaml rule as every other string here.
        const question = I18n.get( "api_keys.revoke_confirm" );
        if ( !( await Dom.confirm( question ) ) ) return;
        try {
          await revoke( key.id );
          await Keys.refresh();
          if ( Keys.me.role === "admin" ) await Keys.refreshAll();
        } catch ( error ) { App.showError( error.message ); }
      } },
    } );
  },

  // Changing when a key expires. Only on a live key, since the server will not
  // revive a dead one, and with no undo: it counts from today, so there is no
  // exact old date to go back to, and the dialog already asked.
  expiryButton( key , setExpiry ) {
    const text = I18n.get( "api_keys.expiry_button" );
    if ( !key.live || text === "" ) return null;
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-secondary",
      text: text,
      on: { click: async function () {
        const saved = await Dom.form( {
          title: I18n.get( "api_keys.expiry_heading" ).replace( "{name}" , () => key.name ),
          fields: [ {
            name: "days",
            label: I18n.get( "api_keys.days_label" ),
            type: "number",
            min: 0,
            max: 3650,
            required: true,
            help: I18n.get( "api_keys.expiry_help" ),
          } ],
          save: ( values ) => setExpiry( key.id , values.days ),
        } );
        if ( saved === null ) return;
        try {
          await Keys.refreshBoth();
        } catch ( error ) { App.showError( error.message ); }
        Dom.toast( I18n.get( "api_keys.expiry_changed" ) , "ok" );
      } },
    } );
  },

  // Whether the server would let this admin change a key's expiry: their own, or
  // one they could have minted, which is the same rule. refreshAll loads the
  // accounts this looks at first.
  mayExtend( key ) {
    return key.user_id === this.me.id || this.targets.has( String( key.user_id ) );
  },

  deleteButton( key , remove , restore ) {
    return Dom.el( "button" , {
      class: "btn btn-sm btn-outline-danger",
      text: I18n.get( "api_keys.delete_button" ),
      on: { click: async function () {
        try {
          await remove( key.id );
          await Keys.refreshBoth();
        } catch ( error ) {
          App.showError( error.message );
          return;
        }
        Undo.record( {
          label: I18n.get( "undo.deleted_key" ),
          toast: true,
          undo: async () => { await restore( key.id ); await Keys.refreshBoth(); },
          redo: async () => { await remove( key.id ); await Keys.refreshBoth(); },
        } );
      } },
    } );
  },

  async refreshBoth() {
    await Keys.refresh();
    if ( Keys.me.role === "admin" ) await Keys.refreshAll();
  },

  async refresh() {
    const body = Dom.get( "keys-table" ).querySelector( "tbody" );
    await Pager.load( "keys-table" , "keys" , ( offset ) => Api.listKeys( offset ) , function ( key ) {
      // createElement + textContent throughout: a key's name is free text its
      // owner typed. See the note at the top of dom.js.
      body.appendChild( Dom.el( "tr" , { children: [
        Keys.nameCell( key , ( id , name , expect ) => Api.renameKey( id , name , expect ) ,
          async () => { if ( Keys.me.role === "admin" ) await Keys.refreshAll(); } ),
        Dom.el( "td" , { text: key.role } ),
        Dom.el( "td" , { children: [ Keys.statusBadge( key ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( key.last_used_at , I18n.get( "api_keys.never" ) ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( key.expires_at , I18n.get( "api_keys.never" ) ) ] } ),
        Dom.el( "td" , { children: [
          Dom.el( "div" , { class: "row-actions" , children: [
            Keys.expiryButton( key , function ( id , days ) { return Api.setKeyExpiry( id , days ); } ),
            Keys.revokeButton( key , function ( id ) { return Api.revokeKey( id ); } ),
            Keys.deleteButton( key , function ( id ) { return Api.deleteKey( id ); } , function ( id ) { return Api.restoreKey( id ); } ),
          ].filter( Boolean ) } ),
        ] } ),
      ] } ) );
    } );
  },

  async refreshAll() {
    await this.loadTargets();
    const body = Dom.get( "admin-keys-table" ).querySelector( "tbody" );
    await Pager.load( "admin-keys-table" , "keys" , ( offset ) => Api.listAllKeys( offset ) , function ( key ) {
      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { text: key.display_name || ( "#" + key.user_id ) } ),
        Keys.nameCell( key , ( id , name , expect ) => Api.renameAnyKey( id , name , expect ) , () => Keys.refresh() ),
        Dom.el( "td" , { text: key.role } ),
        Dom.el( "td" , { children: [ Keys.statusBadge( key ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( key.last_used_at , I18n.get( "api_keys.never" ) ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( key.expires_at , I18n.get( "api_keys.never" ) ) ] } ),
        Dom.el( "td" , { children: [
          Dom.el( "div" , { class: "row-actions" , children: [
            Keys.mayExtend( key ) ? Keys.expiryButton( key , function ( id , days ) { return Api.setAnyKeyExpiry( id , days ); } ) : null,
            Keys.revokeButton( key , function ( id ) { return Api.revokeAnyKey( id ); } ),
            Keys.deleteButton( key , function ( id ) { return Api.deleteAnyKey( id ); } , function ( id ) { return Api.restoreAnyKey( id ); } ),
          ].filter( Boolean ) } ),
        ] } ),
      ] } ) );
    } );
  },
};
