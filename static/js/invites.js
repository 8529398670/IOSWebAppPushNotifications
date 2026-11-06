// The invite links panel (admin only): one link a whole group can join
// through. app.js calls Invites.init( me ) once it knows the viewer is an
// admin; the server checks again on every call.
const Invites = {
  async init( me ) {
    if ( me.role !== "admin" || me.invite_links_enabled === false ) return;
    Dom.show( Dom.get( "invite-links-panel" ) , true );
    Dom.onSubmit( Dom.get( "create-invite-form" ) , this.onCreate.bind( this ) );
    Dom.get( "copy-invite-button" ).addEventListener( "click" , this.onCopy.bind( this ) );
    Qr.toggle( Dom.get( "invite-link-qr-button" ) , Dom.get( "invite-link-qr" ) , Dom.get( "invite-link-value" ) );
    await this.refresh();
  },

  async onCreate( event ) {
    event.preventDefault();
    const label = Dom.get( "invite-label" ).value.trim();
    const maxUses = parseInt( Dom.get( "invite-uses" ).value , 10 );
    const days = parseInt( Dom.get( "invite-days" ).value , 10 );
    try {
      const created = await Api.createInvite( label , maxUses , days );
      // A path, not a URL, for the same reason as a login link: the browser
      // knows its public origin, the server behind a proxy may not.
      Dom.text( Dom.get( "invite-link-value" ) , window.location.origin + created.join_path );
      Qr.hide( Dom.get( "invite-link-qr" ) );
      Dom.show( Dom.get( "invite-link-box" ) , true );
      Dom.get( "invite-label" ).value = "";
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async onCopy() {
    await Dom.copy( Dom.get( "invite-link-value" ) );
  },

  status( link ) {
    if ( link.revoked ) return Dom.badge( I18n.get( "invite_links.status_revoked" ) , "secondary" );
    if ( new Date( link.expires_at ) <= new Date() ) return Dom.badge( I18n.get( "invite_links.status_expired" ) , "warning" );
    if ( !link.live ) return Dom.badge( I18n.get( "invite_links.status_orphaned" ) , "warning" );
    if ( link.remaining <= 0 ) return Dom.badge( I18n.get( "invite_links.status_full" ) , "secondary" );
    return Dom.badge( I18n.get( "invite_links.status_live" ) , "success" );
  },

  async refresh() {
    const body = Dom.get( "invite-links-table" ).querySelector( "tbody" );
    await Pager.load( "invite-links-table" , "invite_links" , ( offset ) => Api.listInvites( offset ) , function ( link ) {
      const revokeButton = !link.live ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-danger",
        text: I18n.get( "invite_links.revoke_button" ),
        on: { click: async function () {
          const question = I18n.get( "invite_links.revoke_confirm" );
          if ( !( await Dom.confirm( question ) ) ) return;
          try {
            await Api.revokeInvite( link.id );
            await Invites.refresh();
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Unlike a key, a switched-off link can come back: it is how the people
      // who joined sign in on a new device, and a replacement would lock them
      // out. The same link works again for anyone holding it, so it asks first.
      const switchOnButton = !link.revoked ? null : Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( "invite_links.switch_on_button" ),
        on: { click: async function () {
          if ( !( await Dom.confirm( I18n.get( "invite_links.switch_on_confirm" ) ) ) ) return;
          try {
            await Api.switchOnInvite( link.id );
            await Invites.refresh();
            Dom.toast( I18n.get( "invite_links.switched_on" ) , "ok" );
          } catch ( error ) { App.showError( error.message ); }
        } },
      } );

      // Places and how long it works for. No undo, as with a key's expiry: days
      // count from today, so there is no exact old date to go back to. An
      // expired link can be extended, for the reason above.
      const editButton = Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary",
        text: I18n.get( "invite_links.edit_button" ),
        on: { click: async function () {
          const saved = await Dom.form( {
            title: I18n.get( "invite_links.edit_heading" ).replace( "{label}" , () => link.label ),
            fields: [
              { name: "uses" , label: I18n.get( "invite_links.uses_label" ) , type: "number" , min: Math.max( 1 , link.used ) , max: 1000 , value: link.max_uses , required: true },
              { name: "days" , label: I18n.get( "invite_links.days_label" ) , type: "number" , min: 1 , max: 365 , help: I18n.get( "invite_links.edit_days_help" ) },
            ],
            save: ( values ) => Api.setInviteLimits( link.id , values.uses , values.days ),
          } );
          if ( saved === null ) return;
          try {
            await Invites.refresh();
          } catch ( error ) { App.showError( error.message ); }
          Dom.toast( I18n.get( "invite_links.edited" ) , "ok" );
        } },
      } );

      // Delete asks nothing and offers Undo: the server keeps a deleted link
      // restorable for a few minutes. Revoke stays a confirmed step with no
      // undo (see Keys.revokeButton for why).
      const deleteButton = Dom.el( "button" , {
        class: "btn btn-sm btn-outline-danger",
        text: I18n.get( "invite_links.delete_button" ),
        on: { click: async function () {
          try {
            await Api.deleteInvite( link.id );
            await Invites.refresh();
          } catch ( error ) {
            App.showError( error.message );
            return;
          }
          Undo.record( {
            label: I18n.get( "undo.deleted_invite" ),
            toast: true,
            undo: async () => { await Api.restoreInvite( link.id ); await Invites.refresh(); },
            redo: async () => { await Api.deleteInvite( link.id ); await Invites.refresh(); },
          } );
        } },
      } );

      const joined = I18n.get( "invite_links.joined_of" )
        .replace( "{used}" , String( link.used ) )
        .replace( "{max}" , String( link.max_uses ) );

      // The label edits in place. Dom.editable builds with textContent, never an
      // HTML string: it is admin-typed text.
      const label = Dom.editable( link.label , {
        label: I18n.get( "invite_links.table_label" ),
        maxLength: 80,
        save: async function ( value ) {
          const previous = link.label;
          await Api.renameInvite( link.id , value , previous );
          link.label = value;
          Undo.record( {
            label: I18n.get( "undo.rename_invite" ),
            toast: true,
            undo: async () => { await Api.renameInvite( link.id , previous , value ); await Invites.refresh(); },
            redo: async () => { await Api.renameInvite( link.id , value , previous ); await Invites.refresh(); },
          } );
        },
      } );

      body.appendChild( Dom.el( "tr" , { children: [
        Dom.el( "td" , { children: [ label ] } ),
        Dom.el( "td" , { text: joined } ),
        Dom.el( "td" , { children: [ Invites.status( link ) ] } ),
        Dom.el( "td" , { children: [ Dom.when( link.expires_at ) ] } ),
        Dom.el( "td" , { children: [
          Dom.el( "div" , { class: "row-actions" , children: [ editButton , switchOnButton , revokeButton , deleteButton ].filter( Boolean ) } ),
        ] } ),
      ] } ) );
    } );
  },
};
