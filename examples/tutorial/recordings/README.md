# Tutorial terminal recordings

Short asciinema recordings for the tutorial docs. Four moments where seeing the output beats reading it:

| Cast | Module | Published | What it shows |
|------|--------|-----------|---------------|
| `m01-hello` | 1 | [a/GWQ1rUgWufRxMUcE](https://asciinema.org/a/GWQ1rUgWufRxMUcE) | the first allow and deny |
| `m03-shaping` | 3 | [a/FJscsrCUbnazbPSl](https://asciinema.org/a/FJscsrCUbnazbPSl) | the same record, redacted vs. full |
| `m07-tainting` | 7 | [a/MCo8BWT3DvW7OH8d](https://asciinema.org/a/MCo8BWT3DvW7OH8d) | the write-down block across a session |
| `m08-elicitation` | 8 | [a/xjfOzQwrEnrLLCp8](https://asciinema.org/a/xjfOzQwrEnrLLCp8) | suspend, approve out of band, resume |

> **These uploads are anonymous and must be claimed.** They were published
> from a CLI that is not linked to an account, so asciinema.org will delete
> them after about 7 days unless claimed. To keep them permanently: run
> `asciinema auth`, open the printed URL in a browser while signed in to
> your asciinema.org account, and the recordings from this machine attach
> to it. The docs already embed these ids (see the four module pages).

## Recording and publishing

These are published to [asciinema.org](https://asciinema.org) from a logged-in account, so the casts do not expire and each has its own shareable URL. Unlike a GIF, the player is pausable and seekable, and the terminal text is selectable.

1. Log in once: `asciinema auth` (opens a browser to link this machine to your account).
2. Start the tutorial IdP (modules 7 and 8 need it):
   ```bash
   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
   ```
3. Record each cast (scripts drive the module binaries so the sessions are reproducible):
   ```bash
   ./record.sh          # records all four into ./casts/
   ```
4. Upload each to your account and note the returned id:
   ```bash
   asciinema upload casts/m01-hello.cast     # prints https://asciinema.org/a/<ID>
   ```

## Embedding in the docs

Once a cast is uploaded, add its player to the matching docs page with the hugo-book shortcode, pointing at the public cast on asciinema.org:

```
{{< asciinema cast="https://asciinema.org/a/<ID>.cast" poster="npt:0:03" >}}
```

The player streams the cast from asciinema.org (non-expiring, individually shareable at `asciinema.org/a/<ID>`) while rendering inline in the page. Keep the copyable text output already in each page: it is the accessible fallback and works even if asciinema.org is unreachable.

The casts and the `record.sh` script live here so they can be regenerated and re-uploaded whenever module output changes. `make tutorial-check` catches when a module's output has drifted from what the docs and casts show.
