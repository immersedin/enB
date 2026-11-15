# FTXUI Code Examples

## 1. Static Layout (DOM only, no interaction)

Demonstrates: vbox, hbox, filler, gauge, border, separator, color.

```cpp
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
using namespace ftxui;

int main() {
  auto doc = vbox({
    hbox({
      text("north-west"),
      filler(),
      text("north-east"),
    }),
    filler(),
    hbox({filler(), text("center") | bold, filler()}),
    filler(),
    hbox({
      text("south-west"),
      filler(),
      text("south-east"),
    }),
  });
  auto screen = Screen::Create(Dimension::Full());
  Render(screen, doc);
  screen.Print();
  getchar();
}
```

## 2. Interactive Menu with Callback

Demonstrates: App::TerminalOutput, Menu, MenuOption, ExitLoopClosure.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <iostream>
using namespace ftxui;

int main() {
  auto screen = App::TerminalOutput();

  std::vector<std::string> entries = {"entry 1", "entry 2", "entry 3"};
  int selected = 0;

  MenuOption opt;
  opt.on_enter = screen.ExitLoopClosure();  // Enter confirms and exits
  auto menu = Menu(&entries, &selected, opt);

  screen.Loop(menu);
  std::cout << "Selected: " << entries[selected] << std::endl;
}
```

## 3. Form with Multiple Inputs

Demonstrates: Input, InputOption (password), CatchEvent for validation,
Container::Vertical, Renderer, hbox layout.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;

int main() {
  std::string first_name, last_name, password, phone;

  auto input_first   = Input(&first_name,  "First name");
  auto input_last    = Input(&last_name,   "Last name");
  auto input_pass    = Input(&password,    "Password",
                              InputOption{.password = true});
  auto input_phone   = Input(&phone, "Phone (digits only)");

  // Filter non-digit input for phone field:
  input_phone |= CatchEvent([&](Event e) {
    return e.is_character() && !std::isdigit(e.character()[0]);
  });

  auto form = Container::Vertical({
    input_first, input_last, input_pass, input_phone,
  });

  auto renderer = Renderer(form, [&] {
    auto field = [](const std::string& label, Component c) {
      return hbox({text(label + " : ") | size(WIDTH, EQUAL, 12), c->Render()});
    };
    return vbox({
      text("User Registration") | bold | center,
      separator(),
      field("First name",  input_first),
      field("Last name",   input_last),
      field("Password",    input_pass),
      field("Phone",       input_phone),
      separator(),
      hbox({text("Hello, "), text(first_name + " " + last_name) | bold}),
    }) | border;
  });

  auto screen = App::TerminalOutput();
  screen.Loop(renderer);
}
```

## 4. Buttons with Custom Style

Demonstrates: Button, ButtonOption::Animated, Container::Vertical/Horizontal,
Renderer, EntryState transform.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <string>
using namespace ftxui;

ButtonOption Style() {
  auto opt = ButtonOption::Animated();
  opt.transform = [](const EntryState& s) {
    auto e = text(s.label);
    if (s.focused) e |= bold;
    return e | center | borderEmpty | flex;
  };
  return opt;
}

int main() {
  int value = 50;
  auto btn_dec = Button("-1",  [&] { value--; }, Style());
  auto btn_inc = Button("+1",  [&] { value++; }, Style());
  auto btn_d10 = Button("-10", [&] { value -= 10; }, Style());
  auto btn_i10 = Button("+10", [&] { value += 10; }, Style());

  int row = 0;
  auto buttons = Container::Vertical({
    Container::Horizontal({btn_dec, btn_inc}, &row) | flex,
    Container::Horizontal({btn_d10, btn_i10}, &row) | flex,
  });

  auto comp = Renderer(buttons, [&] {
    return vbox({
      text("value = " + std::to_string(value)),
      separator(),
      buttons->Render() | flex,
    }) | flex | border;
  });

  auto screen = App::FitComponent();
  screen.Loop(comp);
}
```

## 5. Tabs with Radiobox per Tab

Demonstrates: Toggle (tab bar), Container::Tab, Radiobox, Container::Vertical.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;

int main() {
  std::vector<std::string> tab_labels{"Tab 1", "Tab 2", "Tab 3"};
  int tab_selected = 0;
  auto tab_toggle = Toggle(&tab_labels, &tab_selected);

  std::vector<std::string> entries_1{"Forest", "Water",  "Fire"};
  std::vector<std::string> entries_2{"Hello",  "Hi",     "Hey"};
  std::vector<std::string> entries_3{"Table",  "Chair",  "Lamp"};
  int sel1 = 0, sel2 = 0, sel3 = 0;

  auto tab_content = Container::Tab({
    Radiobox(&entries_1, &sel1),
    Radiobox(&entries_2, &sel2),
    Radiobox(&entries_3, &sel3),
  }, &tab_selected);

  auto container = Container::Vertical({tab_toggle, tab_content});
  auto renderer  = Renderer(container, [&] {
    return vbox({
      tab_toggle->Render(),
      separator(),
      tab_content->Render(),
    }) | border;
  });

  auto screen = App::TerminalOutput();
  screen.Loop(renderer);
}
```

## 6. Modal Dialog

Demonstrates: Modal decorator, bool flag, Button, Container::Vertical, Renderer.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;

auto button_style = ButtonOption::Animated();

Component ModalContent(std::function<void()> hide) {
  auto comp = Container::Vertical({
    Button("Do nothing", [] {},  button_style),
    Button("Close",      hide,   button_style),
  });
  comp |= Renderer([&](Element inner) {
    return vbox({text("Modal dialog"), separator(), inner})
      | size(WIDTH, GREATER_THAN, 30) | border;
  });
  return comp;
}

int main() {
  bool modal_open = false;
  auto screen = App::TerminalOutput();

  auto main_comp = Container::Vertical({
    Button("Open modal", [&] { modal_open = true; },  button_style),
    Button("Quit",       screen.ExitLoopClosure(),    button_style),
  });
  main_comp |= Renderer([&](Element inner) {
    return vbox({text("Main screen"), separator(), inner})
      | size(WIDTH, GREATER_THAN, 20) | size(HEIGHT, GREATER_THAN, 10)
      | border | center;
  });

  auto modal = ModalContent([&] { modal_open = false; });
  main_comp |= Modal(modal, &modal_open);

  screen.Loop(main_comp);
}
```

## 7. Four-Panel Resizable Split

Demonstrates: ResizableSplitLeft/Right/Top/Bottom, Renderer, App::Fullscreen.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;

int main() {
  int left_size = 20, right_size = 20, top_size = 10, bottom_size = 10;

  auto panel = [](const char* name, int* sz) {
    return Renderer([name, sz] {
      return text(std::string(name) + ": " + std::to_string(*sz)) | center;
    });
  };

  auto layout = Renderer([] { return text("Center") | center; });
  layout = ResizableSplitLeft(panel("Left",   &left_size),   layout, &left_size);
  layout = ResizableSplitRight(panel("Right", &right_size),  layout, &right_size);
  layout = ResizableSplitTop(panel("Top",     &top_size),    layout, &top_size);
  layout = ResizableSplitBottom(panel("Bot",  &bottom_size), layout, &bottom_size);

  auto renderer = Renderer(layout, [&] {
    return layout->Render() | border;
  });

  auto screen = App::Fullscreen();
  screen.Loop(renderer);
}
```

## 8. Floating Windows (Container::Stacked)

Demonstrates: Window, Container::Stacked, Checkbox, Slider, Make<T>.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
using namespace ftxui;

Component WindowContent() {
  class Impl : public ComponentBase {
    bool chk[3] = {};
    float slider_val = 50.f;
  public:
    Impl() {
      Add(Container::Vertical({
        Checkbox("Option A", &chk[0]),
        Checkbox("Option B", &chk[1]),
        Checkbox("Option C", &chk[2]),
        Slider("Value", &slider_val, 0.f, 100.f, 1.f),
      }));
    }
  };
  return Make<Impl>();
}

int main() {
  int w1l = 10, w1t = 5, w1w = 40, w1h = 15;
  auto w1 = Window({
    .inner  = WindowContent(),
    .title  = "First Window",
    .left   = &w1l, .top    = &w1t,
    .width  = &w1w, .height = &w1h,
  });
  auto w2 = Window({.inner = WindowContent(), .title = "Second",
                    .left = 30, .top = 12});
  auto w3 = Window({.inner = WindowContent(), .title = "Third",
                    .left = 50, .top = 20});

  auto desktop = Container::Stacked({w1, w2, w3});
  auto screen  = App::Fullscreen();
  screen.Loop(desktop);
}
```

## 9. Table with Styling

Demonstrates: Table, SelectRow/Column/All/Cell, Border, Decorate, DecorateCellsAlternateRow.

```cpp
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/dom/node.hpp>
#include <iostream>
using namespace ftxui;

int main() {
  auto table = Table({
    {"Name",     "Score",  "Grade"},
    {"Alice",    "95",     "A"},
    {"Bob",      "82",     "B"},
    {"Charlie",  "71",     "C"},
    {"Diana",    "88",     "B+"},
  });

  table.SelectAll().Border(LIGHT);
  table.SelectRow(0).Decorate(bold);
  table.SelectRow(0).Border(DOUBLE);
  table.SelectRow(0).SeparatorVertical(LIGHT);
  table.SelectColumn(1).DecorateCells(align_right);

  auto body = table.SelectRows(1, -1);
  body.DecorateCellsAlternateRow(color(Color::Blue),  2, 0);
  body.DecorateCellsAlternateRow(color(Color::White), 2, 1);

  auto doc    = table.Render();
  auto screen = Screen::Create(Dimension::Fit(doc, true));
  Render(screen, doc);
  screen.Print();
  std::cout << std::endl;
}
```

## 10. Canvas Drawing

Demonstrates: Canvas, DrawPointLine/Circle/Text, canvas() element.

```cpp
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/canvas.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/dom/node.hpp>
#include <cmath>
using namespace ftxui;

int main() {
  auto c = Canvas(100, 100);

  // Styled text:
  c.DrawText(0, 0, "FTXUI Canvas", [](Cell& p) {
    p.foreground_color = Color::Red;
    p.underlined       = true;
  });

  // Triangle (braille resolution):
  c.DrawPointLine(10, 10, 80, 10, Color::Red);
  c.DrawPointLine(80, 10, 80, 40, Color::Blue);
  c.DrawPointLine(80, 40, 10, 10, Color::Green);

  // Circles:
  c.DrawPointCircle(30, 65, 15);
  c.DrawPointCircleFilled(70, 65, 12);

  // Sine wave plot:
  for (int x = 0; x < 99; ++x) {
    int y1 = int(80 + 15 * std::sin(x       * 0.2));
    int y2 = int(80 + 15 * std::sin((x + 1) * 0.2));
    c.DrawPointLine(x, y1, x + 1, y2, Color::Yellow);
  }

  auto doc    = canvas(&c) | border;
  auto screen = Screen::Create(Dimension::Fit(doc));
  Render(screen, doc);
  screen.Print();
  getchar();
}
```

## 11. Animated Graph (Manual Loop)

Demonstrates: Graph function, Screen::ResetPosition, animation loop, graph element.

```cpp
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/dom/node.hpp>
#include <cmath>
#include <thread>
#include <chrono>
using namespace ftxui;
using namespace std::chrono_literals;

int main() {
  int shift = 0;
  auto my_graph = [&](int w, int h) {
    std::vector<int> out(w);
    for (int x = 0; x < w; ++x)
      out[x] = int(h / 2 + (h / 3) * std::sin((x + shift) * 0.15));
    return out;
  };

  std::string reset_pos;
  for (;;) {
    auto doc    = graph(std::ref(my_graph)) | border
                | size(HEIGHT, GREATER_THAN, 20);
    auto screen = Screen::Create(Dimension::Full(), Dimension::Fit(doc));
    Render(screen, doc);
    std::cout << reset_pos;
    screen.Print();
    reset_pos = screen.ResetPosition();

    std::this_thread::sleep_for(33ms);
    shift++;
  }
}
```

## 12. CatchEvent for Quit Key

Demonstrates: CatchEvent, Event comparison, ExitLoopClosure, custom key bindings.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
using namespace ftxui;

int main() {
  auto screen = App::Fullscreen();

  auto content = Renderer([] {
    return text("Press 'q' to quit, arrow keys to navigate") | center | border;
  });

  content |= CatchEvent([&](Event e) {
    if (e == Event::Character('q') || e == Event::Escape) {
      screen.ExitLoopClosure()();
      return true;
    }
    return false;
  });

  screen.Loop(content);
}
```

## 13. Custom ComponentBase with Animation

Demonstrates: ComponentBase, OnAnimation, RequestAnimationFrame, Make<T>.

```cpp
#include <ftxui/component/app.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/animation.hpp>
#include <ftxui/dom/elements.hpp>
#include <cmath>
using namespace ftxui;

class PulseBar : public ComponentBase {
  float progress_ = 0.f;
  float time_     = 0.f;

public:
  void OnAnimation(animation::Params& p) override {
    time_     += std::chrono::duration<float>(p.duration()).count();
    progress_  = 0.5f + 0.5f * std::sin(time_ * 2.f);
    RequestAnimationFrame();
  }

  Element Render() override {
    return vbox({
      text("Animated gauge") | bold | center,
      gauge(progress_) | color(Color::Green),
      text(std::to_string(int(progress_ * 100)) + "%") | center,
    }) | border;
  }
};

int main() {
  auto comp   = Make<PulseBar>();
  auto screen = App::Fullscreen();
  screen.Loop(comp);
}
```
