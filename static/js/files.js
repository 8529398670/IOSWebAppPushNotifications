// The Files screen: your uploads, and for an admin, everyone's.
//
// A file goes up in pieces, one at a time, the size the server says. The server
// keeps count, so a failed piece is resumed from what it reports rather than
// from what this page believes. See the server's files route for why it works
// this way.
const Files = {
  me: null,
  // Showing everyone's files rather than your own.
  everyone: false,
  // How many times one piece is tried, and how long to wait between tries.
  attempts: 5,
  retryWait: 2000,

  async init( me ) {
    this.me = me;
    // Off in config.yaml, the routes answer 404, so there is nothing to show.
    if ( me.files_enabled === false ) return;
    Dom.show( Dom.get( "files-panel" ) , true );
    Dom.get( "file-input" ).addEventListener( "change" , this.onPick.bind( this ) );
    Dom.get( "file-cancel" ).addEventListener( "click" , () => { this.cancelled = true; } );
    this.watchDrops( Dom.get( "files-panel" ) );
    window.addEventListener( "beforeunload" , ( event ) => {
      if ( this.uploading ) event.preventDefault();
    } );
    if ( me.role === "admin" ) {
      Dom.show( Dom.get( "files-everyone-field" ) , true );
      Dom.get( "files-everyone" ).addEventListener( "change" , this.onEveryone.bind( this ) );
    }
    await this.refresh();
  },

  async onEveryone( event ) {
    this.everyone = event.target.checked;
    Dom.show( Dom.get( "files-owner-column" ) , this.everyone );
    await this.refresh();
  },

  // How much of the quota is gone, so a full account is not news to its owner
  // only when an upload is refused. Quiet if it fails: the list above it works
  // without this.
  async refreshUsage() {
    try {
      const usage = await Api.storage();
      const bar = Dom.get( "files-usage-bar" );
      bar.max = Math.max( usage.quota_bytes , 1 );
      bar.value = usage.used_bytes;
      Dom.text( Dom.get( "files-usage-text" ) , I18n.get( "files.usage" )
        .replace( "{used}" , this.size( usage.used_bytes ) )
        .replace( "{quota}" , this.size( usage.quota_bytes ) ) );
      Dom.show( Dom.get( "files-usage" ) , true );
      if ( this.me.role !== "admin" ) return;
      const all = await Api.allStorage();
      const line = all.disk_free_bytes === undefined ? I18n.get( "files.usage_all" ) : I18n.get( "files.usage_all_disk" );
      Dom.text( Dom.get( "files-usage-all" ) , line
        .replace( "{used}" , this.size( all.used_bytes ) )
        .replace( "{free}" , this.size( all.disk_free_bytes || 0 ) ) );
    } catch ( error ) { /* see above */ }
    Dom.show( Dom.get( "files-usage-all" ) , this.everyone );
  },

  // The whole screen takes a drop: a target the size of a form field is a thing
  // to miss, and a miss makes the browser navigate to the dropped file.
  watchDrops( panel ) {
    const carriesFiles = ( event ) => Array.from( event.dataTransfer.types ).includes( "Files" );
    const mark = ( on ) => panel.classList.toggle( "file-drop-active" , on );
    [ "dragenter" , "dragover" ].forEach( ( name ) => panel.addEventListener( name , ( event ) => {
      if ( !carriesFiles( event ) ) return;
      event.preventDefault();
      mark( true );
    } ) );
    // Leaving a child fires this too, so only leaving the panel itself counts.
    panel.addEventListener( "dragleave" , ( event ) => {
      if ( !panel.contains( event.relatedTarget ) ) mark( false );
    } );
    panel.addEventListener( "drop" , ( event ) => {
      if ( !carriesFiles( event ) ) return;
      event.preventDefault();
      mark( false );
      if ( !this.uploading ) this.uploadAll( Array.from( event.dataTransfer.files ) );
    } );
  },

  onPick( event ) {
    return this.uploadAll( Array.from( event.target.files ) );
  },

  // One after another. One that fails does not stop the rest, since the next
  // may be fine; what failed is said once, at the end. Cancel stops the one in
  // progress and everything after it.
  async uploadAll( picked ) {
    const input = Dom.get( "file-input" );
    input.disabled = true;
    this.uploading = true;
    this.cancelled = false;
    const failed = [];
    let reason = "";
    for ( const file of picked ) {
      if ( this.cancelled ) break;
      try {
        await this.upload( file );
      } catch ( error ) {
        if ( this.cancelled ) break;
        failed.push( file.name );
        reason = error.message;
      }
    }
    this.uploading = false;
    input.value = "";
    input.disabled = false;
    Dom.show( Dom.get( "file-progress-box" ) , false );
    if ( failed.length > 0 ) {
      App.showError( I18n.get( "files.failed_list" )
        .replace( "{names}" , failed.join( ", " ) )
        .replace( "{reason}" , I18n.get( "errors." + reason ) || reason ) );
    }
    await this.refresh();
  },

  showProgress( file , sent ) {
    const bar = Dom.get( "file-progress" );
    bar.max = Math.max( file.size , 1 );
    bar.value = sent;
    Dom.text( Dom.get( "file-progress-text" ) , I18n.get( "files.uploading" )
      .replace( "{name}" , file.name )
      .replace( "{percent}" , String( file.size ? Math.floor( sent * 100 / file.size ) : 100 ) ) );
    Dom.show( Dom.get( "file-progress-box" ) , true );
  },

  async upload( file ) {
    this.showProgress( file , 0 );
    const created = await Api.createFile( file.name , file.size , file.type );
    try {
      let next = 0;
      while ( next < created.chunks ) {
        if ( this.cancelled ) throw new Error( "cancelled" );
        next = await this.sendPiece( created , file , next );
        this.showProgress( file , Math.min( next * created.chunk_bytes , file.size ) );
      }
      await Api.finishFile( created.id );
    } catch ( error ) {
      // Given up on, it would hold its share of the quota until the sweep.
      await Api.deleteFile( created.id ).catch( () => {} );
      throw error;
    }
  },

  // Sends one piece and answers the number of the piece to send next, which
  // is the server's to say: after a lost reply, the piece may already be there.
  async sendPiece( created , file , index ) {
    const start = index * created.chunk_bytes;
    const piece = file.slice( start , start + created.chunk_bytes );
    for ( let attempt = 1 ; ; attempt++ ) {
      try {
        const sent = await Api.sendFileChunk( created.id , index , piece );
        return sent.received;
      } catch ( error ) {
        if ( error.status === 409 && error.payload && error.payload.received !== undefined ) {
          return error.payload.received;
        }
        // No status is the network. A 4xx other than too-many-requests will
        // say the same thing again.
        const passing = !error.status || error.status === 429 || error.status >= 500;
        if ( !passing || attempt >= this.attempts ) throw error;
        await new Promise( ( resolve ) => setTimeout( resolve , this.retryWait * attempt ) );
      }
    }
  },

  size( bytes ) {
    const units = [ [ 1 << 30 , "files.size_gb" ] , [ 1 << 20 , "files.size_mb" ] , [ 1 << 10 , "files.size_kb" ] ];
    for ( const [ scale , key ] of units ) {
      if ( bytes >= scale ) return I18n.get( key ).replace( "{count}" , ( bytes / scale ).toFixed( 1 ) );
    }
    return I18n.get( "files.size_b" ).replace( "{count}" , String( bytes ) );
  },

  async remove( file ) {
    const mine = !this.everyone;
    const remove = () => mine ? Api.deleteFile( file.id ) : Api.deleteAnyFile( file.id );
    const restore = () => mine ? Api.restoreFile( file.id ) : Api.restoreAnyFile( file.id );
    try {
      await remove();
      await this.refresh();
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    Undo.record( {
      label: I18n.get( "undo.deleted_file" ),
      toast: true,
      undo: async () => { await restore(); await this.refresh(); },
      redo: async () => { await remove(); await this.refresh(); },
    } );
  },

  // The name edits in place, with undo. The server cleans it as it does an
  // upload's, so what it answers is what the row shows. It is someone's own
  // text, and Dom.editable builds with textContent.
  nameCell( file , link ) {
    const mine = !this.everyone;
    const rename = ( name , expect ) => mine ? Api.renameFile( file.id , name , expect ) : Api.renameAnyFile( file.id , name , expect );
    return Dom.editable( file.name , {
      label: I18n.get( "files.table_name" ),
      maxLength: 255,
      save: async ( value ) => {
        const previous = file.name;
        const renamed = await rename( value , previous );
        if ( renamed.name === previous ) return previous;
        file.name = renamed.name;
        link.download = renamed.name;
        Undo.record( {
          label: I18n.get( "undo.rename_file" ),
          toast: true,
          undo: async () => { await rename( previous , renamed.name ); await this.refresh(); },
          redo: async () => { await rename( renamed.name , previous ); await this.refresh(); },
        } );
        return renamed.name;
      },
    } );
  },

  renderRow( file ) {
    const path = this.everyone ? Api.anyFileDownloadPath( file.id ) : Api.fileDownloadPath( file.id );
    const download = Dom.el( "a" , {
      class: "btn btn-sm btn-outline-secondary me-1",
      text: I18n.get( "files.download_button" ),
      attrs: { href: path , download: file.name },
    } );
    const cells = [
      Dom.el( "td" , { class: "text-break" , children: [ this.nameCell( file , download ) ] } ),
      Dom.el( "td" , { class: "text-nowrap" , text: this.size( file.size ) } ),
      Dom.el( "td" , { class: "text-nowrap" , children: [ Dom.when( file.created_at ) ] } ),
      Dom.el( "td" , { class: "text-nowrap" , children: [
        download,
        Dom.el( "button" , {
          class: "btn btn-sm btn-outline-danger",
          text: I18n.get( "files.delete_button" ),
          on: { click: () => this.remove( file ) },
        } ),
      ] } ),
    ];
    if ( this.everyone ) cells.splice( 1 , 0 , Dom.el( "td" , { text: file.user_name || ( "#" + file.user_id ) } ) );
    Dom.get( "files-table" ).querySelector( "tbody" ).appendChild( Dom.el( "tr" , { children: cells } ) );
  },

  async refresh() {
    const fetchPage = ( offset ) => this.everyone ? Api.allFiles( offset ) : Api.files( offset );
    const page = await Pager.load( "files-table" , "files" , fetchPage , this.renderRow.bind( this ) );
    if ( page ) Dom.show( Dom.get( "files-empty" ) , page.total === 0 );
    await this.refreshUsage();
  },
};
