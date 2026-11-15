# FTXUI DOM API Reference

## Required Headers

```cpp
#include <ftxui/dom/elements.hpp>   // all elements, decorators, layout
#include <ftxui/dom/table.hpp>      // Table
#include <ftxui/dom/canvas.hpp>     // Canvas
#include <ftxui/dom/node.hpp>       // Render()
#include <ftxui/screen/screen.hpp>  // Screen::Create, Dimension
#include <ftxui/screen/color.hpp>   // Color, LinearGradient
```

## Core Types

```cpp
using Element       = std::shared_ptr<Node>;
using Elements      = std::vector<Element>;
using Decorator     = std::function<Element(Element)>;
using GraphFunction = std::function<std::vector<int>(int width, int height)>;
```

## Screen Creation and Rendering

```cpp
// Dimension options:
Screen::Create(Dimension::Full())                      // full terminal size
Screen::Create(Dimension::Fit(doc))                    // shrink to fit document
Screen::Create(Dimension::Fixed(80), Dimension::Fixed(24))
Screen::Create(Dimension::Full(), Dimension::Fit(doc)) // full width, fit height

Render(screen, document);    // draw element onto screen grid
screen.Print();              // flush to stdout
screen.ResetPosition();      // returns ANSI string to rewind cursor (animation loops)

// Terminal info:
#include <ftxui/screen/terminal.hpp>
Terminal::Size()             // returns Dimensions{dimx, dimy}
Terminal::ColorSupport()     // returns Color::Palette1/16/256/TrueColor
Terminal::GetQuirks()        // returns Quirks struct
Terminal::SetQuirks(quirks)  // override terminal detection
```

## Text Elements

```cpp
text("hello world")              // single-line UTF-8 text
text(L"wide string")             // wstring variant
vtext("abc")                     // vertical text (chars stacked top-to-bottom)
vtext(L"wide")

paragraph("long text...")        // wraps at container width (left-aligned)
paragraphAlignLeft("text")
paragraphAlignRight("text")
paragraphAlignCenter("text")
paragraphAlignJustify("text")
```

## Layout Containers

```cpp
vbox({e1, e2, e3})               // vertical stack
hbox({e1, e2, e3})               // horizontal stack
dbox({background, foreground})   // z-stack (foreground drawn on top)

flexbox(children, FlexboxConfig{
  .direction    = Direction::Right,  // main axis
  .wrap         = FlexboxConfig::Wrap::Wrap,
  .justify_content = FlexboxConfig::JustifyContent::FlexStart,
  .align_items  = FlexboxConfig::AlignItems::Stretch,
  .gap_x = 0, .gap_y = 0,
})

hflow(children)                  // horizontal flow with wrapping
vflow(children)                  // vertical flow with wrapping
gridbox(std::vector<Elements>{{row0col0, row0col1}, {row1col0, row1col1}})
```

## Borders

```cpp
// Direct functions:
border(e)             // LIGHT border (default)
borderLight(e)
borderDashed(e)
borderHeavy(e)
borderDouble(e)
borderRounded(e)
borderEmpty(e)        // invisible border (adds padding only)

// As pipe-able decorators:
e | borderStyled(ROUNDED)
e | borderStyled(Color::Blue)
e | borderStyled(HEAVY, Color::Red)
e | borderWith(Cell{})       // fully custom border cell

// Window with title bar:
window(text("Title"), content)
window(text("Title"), content, ROUNDED)  // with BorderStyle
```

## Separators

```cpp
separator()                      // auto-orients based on container (h in vbox, v in hbox)
separatorLight()
separatorDashed()
separatorHeavy()
separatorDouble()
separatorEmpty()                 // invisible separator (spacing only)
separatorStyled(DASHED)
separatorCharacter("─")          // custom string repeated
separator(Cell{})                // custom Cell

// Animated selection indicators:
separatorHSelector(float left, float right, Color unselected, Color selected)
separatorVSelector(float up,   float down,  Color unselected, Color selected)
```

## Text Style Decorators

```cpp
bold(e)             // bold / bright
dim(e)              // dim / faint
italic(e)           // italic
underlined(e)       // single underline
underlinedDouble(e) // double underline
strikethrough(e)    // strikethrough
blink(e)            // blinking (terminal-dependent)
inverted(e)         // swap foreground and background colors
```

## Colors

### Named Colors (`Color::` prefix)

Standard:   `Black`, `White`, `Red`, `Green`, `Blue`, `Yellow`, `Cyan`, `Magenta`
Light:      `RedLight`, `GreenLight`, `BlueLight`, `YellowLight`, `CyanLight`, `MagentaLight`, `WhiteLight`
Dark:       `GrayDark`, `GrayLight`
Extended:   `Red1`..`Red3`, `Blue1`..`Blue3`, `Green1`..`Green3`, etc.
Special:    `Default` (terminal default), `Transparent`

### True Color and Palette

```cpp
Color::RGB(uint8_t r, uint8_t g, uint8_t b)   // 0-255 per channel
Color::HSV(uint8_t h, uint8_t s, uint8_t v)   // h=0..255, s=0..255, v=0..255
Color::Palette256(uint8_t index)               // 256-color terminal palette

// Apply to elements:
color(Color::Red, element)         // foreground
bgcolor(Color::Blue, element)      // background
element | color(Color::Red)        // pipe form
element | bgcolor(Color::Blue)
```

### Linear Gradients

```cpp
LinearGradient grad;
grad.angle = 45.0f;                              // 0=left→right, 90=top→bottom
grad.stops.push_back({Color::Red,  0.0f});
grad.stops.push_back({Color::Blue, 1.0f});

color(grad, element)
bgcolor(grad, element)
element | color(grad)
element | bgcolor(grad)
```

## Progress Gauges

All values: `float` in `[0.0, 1.0]`.

```cpp
gauge(0.5f)                        // left → right (default)
gaugeRight(0.5f)                   // left → right
gaugeLeft(0.5f)                    // right → left
gaugeUp(0.5f)                      // bottom → top
gaugeDown(0.5f)                    // top → bottom
gaugeDirection(0.5f, Direction::Up)
```

## Spinner (ASCII Animation)

```cpp
// charset_index 0–8 selects animation style
// image_index is the current frame (increment each render cycle)
spinner(int charset_index, size_t image_index)

// Example (in animation loop):
size_t frame = 0;
auto doc = spinner(5, frame++) | border;
```

## Size Constraints

```cpp
// WidthOrHeight: WIDTH or HEIGHT
// Constraint:   LESS_THAN, EQUAL, GREATER_THAN
element | size(WIDTH,  GREATER_THAN, 20)
element | size(HEIGHT, EQUAL,        5)
element | size(WIDTH,  LESS_THAN,    40)
```

## Flex and Alignment

```cpp
// Flex: controls how extra space is distributed
flex(e)          // grow AND shrink along main axis
xflex(e)         // flex on x-axis only
yflex(e)         // flex on y-axis only
flex_grow(e)     // absorb extra space, don't shrink
xflex_grow(e)
yflex_grow(e)
flex_shrink(e)   // give up space if tight, don't grow
xflex_shrink(e)
yflex_shrink(e)
notflex(e)       // explicitly disable flex
filler()         // an element that just expands to fill remaining space

// Alignment:
hcenter(e)       // center horizontally within parent
vcenter(e)       // center vertically within parent
center(e)        // center both axes
align_right(e)   // align to right edge
```

## Scroll Indicators

```cpp
vscroll_indicator(e)   // adds a vertical scrollbar beside element
hscroll_indicator(e)   // adds a horizontal scrollbar below element
```

## Focus and Cursor Shape

These control the text cursor appearance when an element is focused:

```cpp
focus(e)                           // request focus on this element
focusCursorBlock(e)                // block cursor (█)
focusCursorBlockBlinking(e)        // blinking block
focusCursorBar(e)                  // bar / I-beam (|)
focusCursorBarBlinking(e)          // blinking bar
focusCursorUnderline(e)            // underline cursor (_)
focusCursorUnderlineBlinking(e)    // blinking underline

focusPosition(int x, int y)        // scroll container to show this cell position
focusPositionRelative(float x, float y)  // proportional 0.0..1.0
```

## Hyperlinks

```cpp
hyperlink("https://example.com", element)
element | hyperlink("https://example.com")
```

## Miscellaneous

```cpp
emptyElement()       // zero-size placeholder element
nothing(e)           // identity (no-op) decorator
automerge(e)         // merge adjacent Unicode box-drawing chars at edges
clear_under(e)       // erase cells behind this element (for dbox layers)
```

## Enumerations

```cpp
enum BorderStyle : uint8_t { LIGHT, DASHED, HEAVY, DOUBLE, ROUNDED, EMPTY };
enum class Direction : uint8_t { Up, Down, Left, Right };
enum WidthOrHeight : uint8_t { WIDTH, HEIGHT };
enum Constraint    : uint8_t { LESS_THAN, EQUAL, GREATER_THAN };
```

---

## Table

```cpp
#include <ftxui/dom/table.hpp>

// Construct from 2D initializer list of strings:
auto table = Table({
  {"Version", "Name",          "Date"},    // header row (index 0)
  {"1.0",     "Alpha",         "2020"},
  {"2.0",     "Beta",          "2021"},
});

// Selection API (indices are 0-based; negative = from end, -1 = last):
table.SelectAll()
table.SelectRow(0)                    // single row
table.SelectRows(1, -1)              // range [1, last]
table.SelectColumn(0)                 // single column
table.SelectColumns(1, 3)            // range
table.SelectCell(col, row)           // single cell

// Styling on a selection:
selection.Border(LIGHT)
selection.Border(LIGHT, color(Color::Red))
selection.Decorate(bold)             // apply decorator to whole cell element
selection.DecorateCells(align_right) // apply decorator to cell content only
selection.SeparatorVertical(LIGHT)
selection.SeparatorHorizontal(LIGHT)
// Alternating row colors (step=3, offset=0/1/2 for 3-stripe pattern):
selection.DecorateCellsAlternateRow(color(Color::Blue),  3, 0)
selection.DecorateCellsAlternateRow(color(Color::Cyan),  3, 1)
selection.DecorateCellsAlternateRow(color(Color::White), 3, 2)

// Render to Element:
auto element = table.Render();
auto screen  = Screen::Create(Dimension::Fit(element, /*extend_beyond_screen=*/true));
Render(screen, element);
```

---

## Graph

```cpp
// GraphFunction: takes (width, height) of the drawing area,
// returns a vector<int> of length `width` with y-values (0 = bottom).

auto my_graph = [](int w, int h) -> std::vector<int> {
  std::vector<int> out(w);
  for (int x = 0; x < w; ++x)
    out[x] = int(h / 2 + (h / 3) * sin(x * 0.15));
  return out;
};

graph(my_graph)                         // element
graph(my_graph) | color(Color::Green)   // colored
graph(std::ref(stateful_obj))           // pass by ref for stateful objects with operator()
```

---

## Canvas

Canvas uses braille characters for high-resolution drawing (each terminal cell = 2×4 braille dots).

```cpp
#include <ftxui/dom/canvas.hpp>

// Create a canvas:
auto c = Canvas(width, height);   // dimensions in braille units (not terminal cells)

// --- Point (braille) drawing: ---
c.DrawPointLine(x1, y1, x2, y2)
c.DrawPointLine(x1, y1, x2, y2, Color::Red)
c.DrawPointCircle(cx, cy, radius)
c.DrawPointCircleFilled(cx, cy, radius)
c.DrawPointEllipse(cx, cy, rx, ry)
c.DrawPointEllipseFilled(cx, cy, rx, ry)

// --- Block character drawing (lower resolution): ---
c.DrawBlockLine(x1, y1, x2, y2)
c.DrawBlockLine(x1, y1, x2, y2, Color::Blue)
c.DrawBlockCircle(cx, cy, radius)
c.DrawBlockCircleFilled(cx, cy, radius)
c.DrawBlockEllipse(cx, cy, rx, ry)
c.DrawBlockEllipseFilled(cx, cy, rx, ry)

// --- Text on canvas: ---
c.DrawText(x, y, "text")
c.DrawText(x, y, "text", [](Cell& cell) {
  cell.foreground_color = Color::Red;
  cell.underlined       = true;
  cell.bold             = true;
})

// --- Create DOM element: ---
canvas(&c) | border

// Lambda form (re-drawn every frame, good for animation):
canvas(width, height, [&frame](Canvas& c) {
  c.DrawText(0, 0, "frame: " + std::to_string(frame));
  c.DrawPointCircle(50, 50, 20 + frame % 10);
}) | border
```
