# Tutorial demos

These are focused recordings of the real disposable lab used by
[`../../tutorial.md`](../../tutorial.md). Each walkthrough is saved as an
[asciinema](https://asciinema.org) `.cast` and rendered to a `.gif` with
[`agg`](https://github.com/asciinema/agg).

Play a cast in a real terminal:

```console
asciinema play docs/tutorial/demos/01-quickstart.cast
```

| Cast | Tutorial section |
|---|---|
| `01-quickstart` | JA4 conformance, profiled HTTP, and intercepted HTTPS |
| `02-profile-precedence` | Live profile changes and a more-specific host route |
| `03-legacy-fallback` | Profile-first TLS with an allowlisted TLS 1.0 retry |

## Re-recording

Start the lab, then record all or a selected set:

```console
./lab/mimic-lab up
./docs/tutorial/demos/record                 # casts and GIFs
./docs/tutorial/demos/record 01 03           # selected walkthroughs
./docs/tutorial/demos/record --no-gif        # casts only
./docs/tutorial/demos/record --render        # GIFs from existing casts
./docs/tutorial/demos/record --render 02     # one existing cast
```

Recording requires `asciinema` (`uv tool install asciinema`) and `jq`. GIF
rendering also requires `agg` (`cargo install --git
https://github.com/asciinema/agg`). The terminal defaults to 110×34 at 14 px;
override `COLS`, `ROWS`, `TYPE_DELAY`, `PRE_RUN`, `POST_RUN`,
`COMMENT_PAUSE`, or `IDLE_LIMIT` when needed.

The driver types and runs the same lab commands shown in the tutorial. It does
not upload casts to asciinema.org; the `.cast` and `.gif` files stay in this
directory and are intended to be committed together.
