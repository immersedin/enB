---
name: fxtui-guide-cpp
description: Expert reference guide for the FTXUI (also written FXTUI) C++ terminal UI framework. Auto-activates when developing terminal user interfaces in C++ using FTXUI, writing TUI components, creating interactive CLI apps, or when user asks about FTXUI elements, components, layout, colors, canvas, tables, animation, screens, gauges, spinners, menus, inputs, buttons, checkboxes, or event handling. Use when: adding FTXUI to a C++ project, building terminal dashboards, implementing TUI widgets, drawing braille canvas graphics, creating modal dialogs, resizable panels, or debugging FTXUI rendering. Do NOT use for other C++ GUI or TUI frameworks (Qt, wxWidgets, ncurses, ImGui, termbox).
---

# FTXUI C++ Terminal UI Guide

FTXUI is a zero-dependency, cross-platform C++ library (C++17) for building terminal UIs, using a functional React-inspired compositional model.

## Architecture: Three Modules

| Module | Link target | Main header | Purpose |
|--------|-------------|-------------|---------|
| screen | `ftxui::screen` | `<ftxui/screen/screen.hpp>` | Terminal rendering, color detection |
| dom | `ftxui::dom` | `<ftxui/dom/elements.hpp>` | Layout, styling, all visual elements |
| component | `ftxui::component` | `<ftxui/component/component.hpp>` | Widgets, event loop, interactivity |

## CMake Setup (Recommended: FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG v7.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(my_app main.cpp)
target_link_libraries(my_app
  PRIVATE ftxui::screen
  PRIVATE ftxui::dom
  PRIVATE ftxui::component
)
```

Alternative: `find_package(ftxui REQUIRED)` for system-installed or vcpkg/Conan installs.

## Decision Guide

| Goal | Use |
|------|-----|
| Print a styled layout and exit | Screen + DOM only |
| Interactive app (menus, inputs, events) | Component + App |
| Animated terminal without interaction | Screen + DOM + manual render loop |
| Custom widget with full control | Inherit `ComponentBase` |

## Static UI Pattern (DOM only)

```cpp
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
using namespace ftxui;

int main() {
  auto doc = vbox({
    text("My App") | bold | center,
    separator(),
    hbox({
      text("Left panel") | border,
      vbox({text("Main"), separator(), text("footer") | dim}) | border | flex,
    }),
    gauge(0.75f) | color(Color::Green),
  });
  auto screen = Screen::Create(Dimension::Full(), Dimension::Fit(doc));
  Render(screen, doc);
  screen.Print();
}
```

## Interactive App Pattern (Component)

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;

int main() {
  int selected = 0;
  std::vector<std::string> entries = {"Option A", "Option B", "Quit"};
  
  auto screen = App::TerminalOutput();
  MenuOption opt;
  opt.on_enter = screen.ExitLoopClosure();
  auto menu = Menu(&entries, &selected, opt);
  
  screen.Loop(menu);
}
```

## App Factory Methods

| Factory | Behavior |
|---------|----------|
| `App::TerminalOutput()` | Runs below existing terminal output, scrolls naturally |
| `App::Fullscreen()` | Takes the full terminal (clears and restores on exit) |
| `App::FitComponent()` | Resizes terminal area to match the component |

`screen.ExitLoopClosure()` returns `std::function<void()>` — call it to quit.

## Pipe Operator (|) — Core Idiom

The `|` operator applies decorators. Left-to-right, same as function nesting right-to-left:

```cpp
text("hello") | bold | color(Color::Red) | border
// equivalent to: border(color(Color::Red, bold(text("hello"))))

// In-place on a Component:
my_component |= Renderer([&](Element inner) {
  return vbox({text("header"), inner}) | border;
});
```

## Layout Essentials

```cpp
vbox({e1, e2, e3})   // children stacked top-to-bottom
hbox({e1, e2, e3})   // children side-by-side
dbox({e1, e2})       // children overlaid (e2 draws on top of e1)

// Space distribution:
hbox({text("fixed"), text("grows") | flex})
hbox({text("Left"), filler(), text("Right")})  // filler pushes right
```

## References

For complete API details and patterns, load on demand:

- **DOM elements, decorators, colors, table, canvas, graph, spinner**: [references/dom-api.md](references/dom-api.md)
- **Component widgets, containers, options, events, animation**: [references/component-api.md](references/component-api.md)
- **Full working code examples**: [references/examples.md](references/examples.md)

### Final Step — Record Usage

Run after the skill's primary task completes:

```bash
python3 ${PWD}/.claude/skills/skill-stat/scripts/record-stat.py "fxtui-guide-cpp"
```
