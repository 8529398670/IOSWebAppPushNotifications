// Fills a table from a paged list route (see pagination in the server) and
// offers "Load more" under it while there are rows left.
//
// A refresh is a load from the start: it replaces the rows and the button, so
// a change on the screen never leaves a stale page behind. Rows come from
// renderRow, which appends one to the table the same way a plain forEach would.
const Pager = {
  // table is the table's id, field the name its rows arrive under, fetchPage
  // calls the Api with an offset. Answers the page, or null if the call failed.
  async load( table , field , fetchPage , renderRow , offset ) {
    const element = Dom.get( table );
    let page;
    try {
      page = await fetchPage( offset );
    } catch ( error ) {
      App.showError( error.message );
      return null;
    }
    if ( !offset ) Dom.clear( element.querySelector( "tbody" ) );
    page[ field ].forEach( renderRow );
    if ( !offset && page[ field ].length === 0 ) this.empty( element );

    const holder = element.closest( ".table-responsive" ) || element;
    const old = holder.parentElement.querySelector( ".pager-more[data-for='" + table + "']" );
    if ( old ) old.remove();
    if ( page.next !== null && page.next !== undefined ) {
      // Busy until the page is in: a second press would fetch the same offset
      // and append those rows twice.
      const more = Dom.el( "button" , {
        class: "btn btn-sm btn-outline-secondary mt-2 pager-more",
        attrs: { "data-for": table },
        text: I18n.get( "ui.load_more" ),
        on: { click: () => Dom.busy( more , () => this.load( table , field , fetchPage , renderRow , page.next ) ) },
      } );
      holder.after( more );
    }
    return page;
  },

  // One row saying there is nothing here, worded by the table's data-empty
  // key, so a bare heading row does not look like a screen that failed to load.
  empty( table ) {
    const text = I18n.get( table.getAttribute( "data-empty" ) || "" );
    if ( text === "" ) return;
    table.querySelector( "tbody" ).appendChild( Dom.el( "tr" , { children: [
      Dom.el( "td" , {
        class: "text-body-secondary",
        text: text,
        attrs: { colspan: String( table.querySelectorAll( "thead th:not([hidden])" ).length ) },
      } ),
    ] } ) );
  },
};
