package logx

import (
	"cmp"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// maxDepth bounds how deep a composite value is walked; deeper values render
// as "<TypeName>".
const maxDepth = 8

var (
	logValuerType = reflect.TypeFor[slog.LogValuer]()
	stringerType  = reflect.TypeFor[fmt.Stringer]()
	errorType     = reflect.TypeFor[error]()
	readerType    = reflect.TypeFor[io.Reader]()
	writerType    = reflect.TypeFor[io.Writer]()
	urlType       = reflect.TypeFor[url.URL]()
	userinfoType  = reflect.TypeFor[url.Userinfo]()
)

// visit identifies a pointer, map or slice currently being walked, for cycle
// detection. The type is part of the key so a struct and its first field,
// which share an address, are not mistaken for each other.
type visit struct {
	t reflect.Type
	p uintptr
}

// walker renders an arbitrary value to a string, masking sensitive map keys
// and struct fields, byte values and anything it cannot inspect safely. It
// stops writing once the output exceeds limit: the caller caps it anyway.
type walker struct {
	h     *Handler
	b     strings.Builder
	limit int
	full  bool // output exceeded limit and was cut short
	seen  map[visit]bool
}

// render turns an arbitrary value into one cleaned, capped string, so the
// inner handler never dumps a raw struct, map or slice. A panic raised by a
// String, Error or LogValue method fails closed to Mask.
func (h *Handler) render(x any) (out string) {
	defer func() {
		if recover() != nil {
			out = Mask
		}
	}()
	w := walker{h: h, limit: h.maxErr, seen: map[visit]bool{}}
	w.value(reflect.ValueOf(x), 0)
	return h.capStr(Clean(w.b.String()), w.full)
}

// stop reports whether the output is already long enough to be cut.
func (w *walker) stop() bool {
	if w.b.Len() > w.limit {
		w.full = true
	}
	return w.full
}

// opaque writes "<TypeName>" for a value the walker refuses to inspect.
func (w *walker) opaque(t reflect.Type) {
	w.b.WriteString("<" + t.String() + ">")
}

// isBytes reports whether t is a byte slice or array, named or not.
func isBytes(t reflect.Type) bool {
	k := t.Kind()
	return (k == reflect.Slice || k == reflect.Array) && t.Elem().Kind() == reflect.Uint8
}

// nilable reports whether a value of kind k may be nil.
func nilable(k reflect.Kind) bool {
	return k == reflect.Interface || k == reflect.Pointer || k == reflect.Map ||
		k == reflect.Slice || k == reflect.Func || k == reflect.Chan
}

// hasMethods reports whether t carries a method that could reveal its
// contents in a way the walker cannot vet.
func hasMethods(t reflect.Type) bool {
	return t.Implements(logValuerType) || t.Implements(stringerType) || t.Implements(errorType)
}

// isStream reports whether t, or a pointer to t, implements io.Reader or
// io.Writer. Such values (buffers, builders, request bodies, files) hold
// content the walker must never print, not even through String().
func isStream(t reflect.Type) bool {
	if t.Implements(readerType) || t.Implements(writerType) {
		return true
	}
	if t.Kind() != reflect.Pointer && t.Kind() != reflect.Interface {
		p := reflect.PointerTo(t)
		return p.Implements(readerType) || p.Implements(writerType)
	}
	return false
}

// value renders v at the given depth. Order: nil, depth bound, URL and
// userinfo, readers and writers, bytes, LogValuer, error, Stringer, then by
// kind.
func (w *walker) value(v reflect.Value, depth int) {
	if w.stop() {
		return
	}
	if !v.IsValid() {
		w.b.WriteString("<nil>")
		return
	}
	if depth > maxDepth {
		w.opaque(v.Type())
		return
	}
	if nilable(v.Kind()) && v.IsNil() {
		w.b.WriteString("<nil>")
		return
	}
	if v.Kind() == reflect.Interface {
		w.value(v.Elem(), depth)
		return
	}
	if w.special(v) {
		return
	}
	if isBytes(v.Type()) {
		w.b.WriteString(Mask)
		return
	}
	if v.CanInterface() {
		if w.methods(v.Interface(), depth) {
			return
		}
	} else if hasMethods(v.Type()) {
		// Unexported field: its methods cannot be called, and printing its
		// raw state would bypass them. Fail closed.
		w.opaque(v.Type())
		return
	}
	w.kind(v, depth)
}

// special renders URLs, userinfo, readers and writers, exported or not, and
// reports whether v was one of them.
func (w *walker) special(v reflect.Value) bool {
	t := v.Type()
	base := t
	if t.Kind() == reflect.Pointer {
		base = t.Elem()
	}
	switch {
	case base == userinfoType:
		w.b.WriteString(Mask)
	case base == urlType:
		if t.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		w.b.WriteString(redactURL(v))
	case isStream(t):
		w.opaque(t)
	default:
		return false
	}
	return true
}

// redactURL renders a url.URL value without its userinfo, query values or
// fragment. It reads the fields through reflection so an unexported field
// is handled too; an opaque part is masked whole.
func redactURL(v reflect.Value) string {
	field := func(name string) string { return v.FieldByName(name).String() }
	u := url.URL{
		Scheme:  field("Scheme"),
		Host:    field("Host"),
		Path:    field("Path"),
		RawPath: field("RawPath"),
	}
	if field("Opaque") != "" {
		u.Opaque = Mask
	}
	s := u.String()
	if field("RawQuery") != "" || field("Fragment") != "" || field("RawFragment") != "" ||
		v.FieldByName("ForceQuery").Bool() {
		s += "?" + Mask
	}
	return s
}

// methods renders x through LogValue, Error or String when it has one, and
// reports whether it did.
func (w *walker) methods(x any, depth int) bool {
	switch t := x.(type) {
	case slog.LogValuer:
		w.slogValue(slog.AnyValue(t).Resolve(), depth+1)
	case error:
		w.b.WriteString(controlFree(Clean(t.Error())))
	case fmt.Stringer:
		w.b.WriteString(Clean(t.String()))
	default:
		return false
	}
	return true
}

// kind renders v by its reflect.Kind.
func (w *walker) kind(v reflect.Value, depth int) {
	switch v.Kind() {
	case reflect.Pointer:
		if w.enter(v) {
			w.b.WriteString("&")
			w.value(v.Elem(), depth+1)
			w.leave(v)
		}
	case reflect.Map:
		if w.enter(v) {
			w.mapValue(v, depth)
			w.leave(v)
		}
	case reflect.Slice:
		if w.enter(v) {
			w.list(v, depth)
			w.leave(v)
		}
	case reflect.Array:
		w.list(v, depth)
	case reflect.Struct:
		w.structValue(v, depth)
	case reflect.String:
		w.b.WriteString(Clean(v.String()))
	case reflect.Bool:
		w.b.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.b.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		w.b.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		w.b.WriteString(strconv.FormatFloat(v.Float(), 'g', -1, 64))
	case reflect.Complex64, reflect.Complex128:
		w.b.WriteString(strconv.FormatComplex(v.Complex(), 'g', -1, 128))
	case reflect.Invalid, reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		w.opaque(v.Type())
	default:
		w.opaque(v.Type()) // a future Kind: fail closed
	}
}

// enter marks v as being walked; it writes "<cycle>" and returns false if
// v is already on the walk stack.
func (w *walker) enter(v reflect.Value) bool {
	k := visit{t: v.Type(), p: v.Pointer()}
	if w.seen[k] {
		w.b.WriteString("<cycle>")
		return false
	}
	w.seen[k] = true
	return true
}

func (w *walker) leave(v reflect.Value) {
	delete(w.seen, visit{t: v.Type(), p: v.Pointer()})
}

// mapKey renders a map key for display and sensitivity matching: a string
// (named or not, possibly inside an interface) is its text, anything else
// its walked form.
func (w *walker) mapKey(k reflect.Value, depth int) string {
	for k.Kind() == reflect.Interface && !k.IsNil() {
		k = k.Elem()
	}
	if k.Kind() == reflect.String {
		return k.String()
	}
	sub := walker{h: w.h, limit: w.limit, seen: w.seen}
	sub.value(k, depth+1)
	return sub.b.String()
}

// mapValue renders a map in key order. A key whose rendered form is
// sensitive masks its value, whatever the key type.
func (w *walker) mapValue(v reflect.Value, depth int) {
	type entry struct {
		key string
		val reflect.Value
	}
	var entries []entry
	for it := v.MapRange(); it.Next(); {
		entries = append(entries, entry{key: w.mapKey(it.Key(), depth), val: it.Value()})
	}
	slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.key, b.key) })
	w.b.WriteString("map[")
	for i, e := range entries {
		if w.stop() {
			return
		}
		if i > 0 {
			w.b.WriteString(" ")
		}
		w.b.WriteString(Clean(e.key) + ":")
		if w.h.sensitive(e.key) {
			w.b.WriteString(Mask)
			continue
		}
		w.value(e.val, depth+1)
	}
	w.b.WriteString("]")
}

// list renders the elements of a slice or array.
func (w *walker) list(v reflect.Value, depth int) {
	w.b.WriteString("[")
	for i := range v.Len() {
		if w.stop() {
			return
		}
		if i > 0 {
			w.b.WriteString(" ")
		}
		w.value(v.Index(i), depth+1)
	}
	w.b.WriteString("]")
}

// structValue renders every field, exported or not; a sensitive field name
// masks its value.
func (w *walker) structValue(v reflect.Value, depth int) {
	t := v.Type()
	w.b.WriteString("{")
	for i := range t.NumField() {
		if w.stop() {
			return
		}
		if i > 0 {
			w.b.WriteString(" ")
		}
		name := t.Field(i).Name
		w.b.WriteString(name + ":")
		if w.h.sensitive(name) {
			w.b.WriteString(Mask)
			continue
		}
		w.value(v.Field(i), depth+1)
	}
	w.b.WriteString("}")
}

// slogValue renders a resolved slog.Value; group members get key masking.
func (w *walker) slogValue(v slog.Value, depth int) {
	switch v.Kind() {
	case slog.KindGroup:
		w.b.WriteString("{")
		for i, a := range v.Group() {
			if w.stop() {
				return
			}
			if i > 0 {
				w.b.WriteString(" ")
			}
			w.b.WriteString(Clean(a.Key) + ":")
			if a.Key != "" && w.h.sensitive(a.Key) {
				w.b.WriteString(Mask)
				continue
			}
			w.slogValue(a.Value.Resolve(), depth+1)
		}
		w.b.WriteString("}")
	case slog.KindAny:
		w.value(reflect.ValueOf(v.Any()), depth)
	case slog.KindString:
		w.b.WriteString(Clean(v.String()))
	case slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64,
		slog.KindTime, slog.KindUint64:
		w.b.WriteString(v.String())
	case slog.KindLogValuer:
		w.b.WriteString(Mask) // unreachable after Resolve: fail closed
	default:
		w.b.WriteString(Mask) // a future Kind: fail closed
	}
}
