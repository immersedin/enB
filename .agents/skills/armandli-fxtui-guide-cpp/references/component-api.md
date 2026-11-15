# FTXUI Component API Reference

## Required Headers

```cpp
#include <ftxui/component/app.hpp>               // App
#include <ftxui/component/component.hpp>          // all component factories
#include <ftxui/component/component_base.hpp>     // ComponentBase (OOP)
#include <ftxui/component/component_options.hpp>  // ButtonOption, InputOption, etc.
#include <ftxui/component/event.hpp>              // Event constants
#include <ftxui/component/mouse.hpp>              // Mouse struct
#include <ftxui/component/animation.hpp>          // animation::Params
```

## App (ScreenInteractive)

```cpp
auto screen = App::TerminalOutput();   // interactive, renders below terminal output
auto screen = App::Fullscreen();       // clears terminal, full-screen mode
auto screen = App::FitComponent();     // resizes region to fit component

screen.Loop(component);                // blocking event loop
screen.ExitLoopClosure()              // returns std::function<void()> to quit
screen.PostEvent(Event::Custom)        // post a custom event from another thread
```

---

## Container Components

Containers hold children and manage focus/navigation automatically.

```cpp
Container::Vertical(children)                // ↑/↓ arrows or j/k
Container::Vertical(children, &selector)     // selector (int*) tracks focused index
Container::Horizontal(children)              // ←/→ arrows or h/l
Container::Horizontal(children, &selector)
Container::Tab(children, &selector)          // only one child active at a time
Container::Stacked(children)                 // children overlap; used with Window
```

Pipe `|` works on `Component` too:
```cpp
auto comp = Container::Vertical({a, b, c}) | border;  // wraps render in border
```

---

## Button

```cpp
Button("Label", on_click)
Button("Label", on_click, ButtonOption)

// ButtonOption presets:
ButtonOption::Simple()      // plain label, no border
ButtonOption::Ascii()       // ASCII box border
ButtonOption::Animated()    // animated color highlight on focus/hover
ButtonOption::Border()      // always-shown border

// Custom appearance via transform:
ButtonOption opt = ButtonOption::Animated();
opt.transform = [](const EntryState& s) {
  auto e = text(s.label) | center;
  if (s.focused) e |= bold;
  if (s.active)  e |= inverted;
  return e | borderEmpty | flex;
};
Button("Go", callback, opt)
```

---

## Checkbox

```cpp
bool checked = false;
Checkbox("Enable feature", &checked)
Checkbox("label", &checked, CheckboxOption)

CheckboxOption opt;
opt.transform = [](const EntryState& s) -> Element {
  return hbox({
    text(s.checked ? "☑ " : "☐ "),
    text(s.label),
  });
};
```

---

## Input

```cpp
std::string content;
std::string placeholder = "type here...";
Input(&content, placeholder)
Input(&content, &placeholder)            // dynamic placeholder
Input(&content, placeholder, InputOption)
Input(InputOption)                       // all in options struct

// InputOption fields:
InputOption opt;
opt.content       = &content;
opt.placeholder   = "hint";
opt.password      = true;               // mask with dots/asterisks
opt.multiline     = true;               // allow Enter to insert newlines
opt.insert_mode   = false;              // false = overwrite mode
opt.on_change     = [&] { validate(); };  // called on every keystroke
opt.on_submit     = [&] { submit(); };    // called on Enter (single-line)
opt.transform     = [](InputState s) {   // s.element is the rendered input
  if (s.focused) s.element |= bold;
  return s.element;
};

// Event filtering example (restrict to digits only):
auto input = Input(&phone, "phone");
input |= CatchEvent([&](Event e) {
  return e.is_character() && !std::isdigit(e.character()[0]);
});
```

---

## Radiobox

```cpp
std::vector<std::string> entries = {"Option A", "Option B", "Option C"};
int selected = 0;
Radiobox(&entries, &selected)
Radiobox(&entries, &selected, RadioboxOption)

RadioboxOption opt;
opt.on_change = [&] { on_select(selected); };
opt.transform = [](const EntryState& s) -> Element {
  return hbox({
    text(s.active ? "◉ " : "○ "),
    text(s.label) | (s.focused ? bold : nothing),
  });
};
```

---

## Slider

```cpp
// Integer:
int value = 50;
Slider("Volume", &value, 0, 100, 1)   // min=0, max=100, step=1

// Float:
float fval = 0.5f;
Slider("Mix", &fval, 0.f, 1.f, 0.01f)

// Directional:
Slider("Height", &value, 0, 100, 1, SliderOption<int>{
  .direction = Direction::Up,         // vertical slider
  .color_active   = Color::Blue,
  .color_inactive = Color::GrayLight,
})

// RGB example (three sliders side by side):
int r = 128, g = 64, b = 200;
auto sliders = Container::Vertical({
  Slider("R:", &r, 0, 255, 1),
  Slider("G:", &g, 0, 255, 1),
  Slider("B:", &b, 0, 255, 1),
});
```

---

## Menu and Toggle

```cpp
// Vertical menu:
std::vector<std::string> entries = {"File", "Edit", "View"};
int selected = 0;
Menu(&entries, &selected)
Menu(&entries, &selected, MenuOption)

MenuOption opt;
opt.on_change   = [&] { refresh(); };
opt.on_enter    = screen.ExitLoopClosure();  // confirm selection
opt.direction   = Direction::Down;           // scroll direction
opt.entries_option.transform = [](const EntryState& s) { ... };

// Individual entry (compose with Container::Vertical for custom layouts):
MenuEntry("Item label")
MenuEntry("Item", MenuEntryOption{
  .transform = [](const EntryState& s) { return text(s.label) | bold; },
})

// Horizontal toggle (same API as Menu):
Toggle(&entries, &selected)    // ←/→ navigation
```

---

## Dropdown

```cpp
Dropdown(&entries, &selected)

Dropdown(DropdownOption{
  .entries   = &entries,
  .selected  = &selected,
  // Custom transform for the closed/open states:
  .transform = [](bool open, Element inner, int selected, const std::vector<std::string>& entries) {
    return inner;
  },
})
```

---

## Collapsible

```cpp
bool open = true;
Collapsible("Section", inner_component)           // toggle state managed internally
Collapsible("Section", inner_component, &open)    // external state control
```

---

## Rendering Components

```cpp
// Pure renderer — no child, no keyboard focus:
Renderer([&] {
  return text("Status: " + status) | color(Color::Green);
})

// Renderer wrapping a child (child handles events, you control output):
Renderer(child, [&] {
  return vbox({
    text("Header") | bold,
    separator(),
    child->Render(),
    separator(),
    text("Footer"),
  }) | border;
})

// With focus parameter:
Renderer(child, [&](bool focused) {
  return child->Render() | (focused ? border : borderEmpty);
})

// Decorator form — attach to existing component:
my_comp |= Renderer([&](Element inner) {
  return vbox({text("Title"), inner}) | border;
});
```

---

## Event Handling

```cpp
CatchEvent(child, [&](Event event) -> bool {
  if (event == Event::Character('q')) { quit(); return true; }
  if (event == Event::Return)         { submit(); return true; }
  return false;  // not consumed → propagates to child
})

// Decorator form:
component |= CatchEvent([&](Event e) -> bool { ... });

// Common Event constants:
Event::Character('a')         // printable character
Event::Return                  // Enter key
Event::Tab / Event::TabReverse // Tab / Shift+Tab
Event::Escape
Event::ArrowUp / ArrowDown / ArrowLeft / ArrowRight
Event::PageUp / Event::PageDown
Event::Home / Event::End
Event::Backspace / Event::Delete
Event::F1 .. Event::F12
Event::Custom                  // user-posted via PostEvent()

// Mouse events:
event.is_mouse()               // true if it's a mouse event
event.mouse().button           // Mouse::Left, Right, Middle, None, WheelUp, WheelDown
event.mouse().motion           // Mouse::Pressed, Released, Moved
event.mouse().x                // terminal column (0-based)
event.mouse().y                // terminal row (0-based)
```

---

## Conditional Display

```cpp
bool show = true;
Maybe(child, &show)                    // hide/show component
Maybe(child, [&] { return show; })     // callback form
child |= Maybe(&show)                  // decorator form

// Modal dialog overlay:
bool modal_open = false;
main_comp |= Modal(modal_component, &modal_open);
// When modal_open=true, modal_component renders centered over main_comp.
```

---

## Hoverable

```cpp
bool hovered = false;
Hoverable(component, &hovered)
Hoverable(component, on_enter_fn, on_leave_fn)        // callbacks
Hoverable(component, [&](bool h) { hovered = h; })    // single callback
```

---

## Window Component

Draggable and resizable floating window. Must be in `Container::Stacked`.

```cpp
int left = 10, top = 5, width = 40, height = 20;
auto win = Window({
  .inner  = my_component,         // component to display inside
  .title  = "My Window",
  .left   = &left,                // pass int* to track position
  .top    = &top,
  .width  = &width,
  .height = &height,
  .resizable_left   = true,       // allow drag-resize from each edge
  .resizable_right  = true,
  .resizable_top    = true,
  .resizable_bottom = true,
});

// Fixed position (pass int literals, not pointers):
Window({.inner = comp, .title = "Fixed", .left = 20, .top = 10})

// Multiple windows must be in Stacked:
auto desktop = Container::Stacked({win1, win2, win3});
```

---

## Resizable Split Panels

```cpp
int left_size = 20, right_size = 20, top_size = 10, bottom_size = 10;

ResizableSplitLeft(left_comp,   right_or_center, &left_size)
ResizableSplitRight(right_comp, left_or_center,  &right_size)
ResizableSplitTop(top_comp,     bottom_or_center, &top_size)
ResizableSplitBottom(bot_comp,  top_or_center,    &bottom_size)

// Four-panel layout (chain from inside out):
auto layout = center_comp;
layout = ResizableSplitLeft(left,   layout, &left_size);
layout = ResizableSplitRight(right, layout, &right_size);
layout = ResizableSplitTop(top,     layout, &top_size);
layout = ResizableSplitBottom(bot,  layout, &bottom_size);
```

---

## Animation

```cpp
// Request a re-draw on the next frame (use in event handlers or OnAnimation):
RequestAnimationFrame();

// Override in a custom ComponentBase subclass:
class AnimComp : public ComponentBase {
  float angle_ = 0.f;
public:
  void OnAnimation(animation::Params& p) override {
    using namespace std::chrono;
    angle_ += duration_cast<duration<float>>(p.duration()).count() * 90.f;
    RequestAnimationFrame();
  }
  Element Render() override {
    return text("angle: " + std::to_string(angle_)) | border;
  }
};
auto comp = Make<AnimComp>();

// Alternatively, animate in a background thread and PostEvent:
std::thread([&screen] {
  while (running) {
    std::this_thread::sleep_for(std::chrono::milliseconds(33));
    screen.PostEvent(Event::Custom);
  }
}).detach();
```

---

## Custom ComponentBase (OOP Style)

```cpp
#include <ftxui/component/component_base.hpp>

class MyWidget : public ComponentBase {
  std::string label_;
  bool        clicked_ = false;
public:
  explicit MyWidget(std::string label) : label_(std::move(label)) {
    // Add child components via Add():
    Add(Button("Reset", [&] { clicked_ = false; }));
  }

  Element Render() override {
    return vbox({
      text(label_) | (clicked_ ? inverted : bold),
      ComponentBase::Render(),   // render children
    }) | border;
  }

  bool OnEvent(Event e) override {
    if (e == Event::Character(' ')) { clicked_ = !clicked_; return true; }
    return ComponentBase::OnEvent(e);   // forward to children
  }
};

// Instantiate with Make<T>:
auto widget = Make<MyWidget>("Hello");
```

---

## EntryState (transform callbacks)

All components accepting a `transform` option pass `EntryState`:

```cpp
struct EntryState {
  std::string label;   // display text for this entry
  bool focused;        // this entry has keyboard focus
  bool hovered;        // mouse cursor is over this entry
  bool active;         // entry is being pressed / is the selected item
  int  index;          // zero-based position in parent container
};
```

---

## Thread Safety Note

`screen.PostEvent()` is the only thread-safe call on `App`. Use it to trigger redraws from background threads; never call `Render()` or modify component state directly from another thread without synchronization.
