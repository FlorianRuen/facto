package browser

// Re-exports for the page tests (J1 T8). The page JavaScript is a fixed set
// of function declarations run through Runtime.callFunctionOn, with the
// selector passed only as arguments[0].value. The fake CDP peer in
// fakecdp_test.go recognises each operation by comparing the declaration
// with these constants.
const (
	// JSVisible: function(sel) -> bool. True when document.querySelector(sel)
	// exists, is connected, has a non-empty box and is not hidden
	// (display, visibility, opacity).
	JSVisible = jsVisible
	// JSCenter: function(sel) -> {x, y} | null. The viewport centre of the
	// visible element, null when missing or not visible.
	JSCenter = jsCenter
	// JSFocus: function(sel) -> bool. Focuses the visible element; false
	// when missing or not visible.
	JSFocus = jsFocus
	// JSActiveCheck: function(sel) -> {matches, activeTag, origin}.
	// matches: document.activeElement === document.querySelector(sel) (an
	// IFRAME/FRAME holding the focus never matches); activeTag: the active
	// element's tagName; origin: location.origin of the main frame.
	JSActiveCheck = jsActiveCheck
)
