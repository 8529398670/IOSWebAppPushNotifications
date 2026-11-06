// The Groups screen: one key that reaches several people. Whoever makes a group
// picks its members, and any member can leave.
const Groups = {
  team: [],

  async init( me ) {
    this.me = me;
    Dom.get( "create-group-button" ).addEventListener( "click" , () => this.edit( null ) );
    await this.loadTeam();
    await this.refresh();
  },

  async loadTeam() {
    const page = await Api.listTeam( 0 );
    this.team = page.members;
  },

  refresh() {
    return Pager.load( "groups-table" , "groups" ,
      ( offset ) => Api.request( "/api/groups" + Api.query( { offset: offset } ) ) ,
      ( group ) => Dom.get( "groups-table" ).querySelector( "tbody" ).appendChild( this.row( group ) ) );
  },

  async edit( group ) {
    const options = this.team.map( ( person ) => ( { value: String( person.id ) , label: person.display_name } ) );
    await Dom.form( {
      title: I18n.get( group ? "groups.edit_heading" : "groups.create_heading" ),
      fields: [
        { name: "name" , label: I18n.get( "groups.name_label" ) , maxLength: 60 , value: group ? group.name : "" , required: true },
        { name: "members" , label: I18n.get( "groups.members_label" ) , type: "checks" , options: options , value: group ? group.members.map( ( member ) => String( member.id ) ) : [] },
      ],
      save: async ( values ) => {
        const body = { name: values.name.trim() , members: values.members.map( Number ) };
        await Api.post( group ? "/api/groups/" + group.id + "/update" : "/api/groups" , body );
        await this.refresh();
      },
    } );
  },

  button( key , tone , onClick ) {
    return Dom.el( "button" , { class: "btn btn-sm btn-outline-" + tone , text: I18n.get( key ) , on: { click: onClick } } );
  },

  row( group ) {
    const key = Dom.el( "code" , { text: group.key } );
    const actions = [ this.button( "account.copy_button" , "secondary" , () => Dom.copy( key ) ) ];
    if ( group.can_manage ) {
      actions.push(
        this.button( "groups.edit_button" , "secondary" , () => this.edit( group ) ),
        this.button( "groups.rotate_button" , "secondary" , () => this.rotate( group ) ),
        this.button( "groups.delete_button" , "danger" , () => this.remove( group ) ),
      );
    }
    if ( group.is_member ) actions.push( this.button( "groups.leave_button" , "secondary" , () => this.leave( group ) ) );

    const names = group.members.map( ( member ) => member.display_name ).join( ", " );
    return Dom.el( "tr" , { children: [ Dom.el( "td" , { children: [
      Dom.el( "div" , { class: "fw-semibold" , text: group.name } ),
      Dom.el( "div" , { class: "small text-body-secondary" , text: names || I18n.get( "groups.no_members" ) } ),
      Dom.el( "div" , { class: "small mt-1 text-break" , children: [ key ] } ),
      Dom.el( "div" , { class: "d-flex flex-wrap gap-2 mt-2" , children: actions } ),
    ] } ) ] } );
  },

  async rotate( group ) {
    if ( !await Dom.confirm( I18n.get( "groups.rotate_confirm" ).replace( "{name}" , () => group.name ) ) ) return;
    try {
      await Api.post( "/api/groups/" + group.id + "/rotate-key" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async leave( group ) {
    if ( !await Dom.confirm( I18n.get( "groups.leave_confirm" ).replace( "{name}" , () => group.name ) ) ) return;
    try {
      await Api.post( "/api/groups/" + group.id + "/leave" );
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
    }
  },

  async remove( group ) {
    try {
      await Undo.run( {
        label: I18n.get( "undo.delete_group" ),
        toast: true,
        do: async () => { await Api.post( "/api/groups/" + group.id + "/delete" ); await this.refresh(); },
        undo: async () => { await Api.post( "/api/groups/" + group.id + "/restore" ); await this.refresh(); },
      } );
    } catch ( error ) {
      App.showError( error.message );
    }
  },
};
