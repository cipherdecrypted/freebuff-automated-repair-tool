# DEPRECATED - A new version will be coming soon, but integrated directly into the freebuff app.

# welcome to fart, aka the freebuff automated repair tool.
## yes i have a sense of humour. 
### also yes that sense of humour matches that of a 5 year old, lmao.

fart, also known as frt, freebuff repair tool, is an automated tool that repairs things. (i know im genius)
it automatically locates your freebuff installation, and scans through a huge library of already observed errors, and can also make its own fixes conditionally, based on the errors presented.
its an amazing tool for the support staff too in the help channels, as you can run this to get a nice large report to hand them, so they can fully understand what is happening with your freebuff.

hope you guys love the tool, it was uh, made out of neccessity, lets say that (dont judge my spelling through this too, be grateful your getting a human written readme for once)

anywaaaaaaaaays yeah, you can run this tool on your own if you want, before even creating a help ticket, as likely chance it can fix it without staff even needing to intervene!

you don't need to install anything too, the repair tool uses the copy of Bun that comes with Freebuff.

# how to run on each os
## Windows:** double-click **`frt.cmd`**.

## macOS:** right-click **`frt.command`** and choose **Open** (later you can just double-click it).

## Linux:** run `./frt.sh`.

# RUN ONLY WHILE FREEBUFF IS CLOSED 
if you run it while freebuff is open, it may cause random issues that we just dont need

also runnable entirely using just the terminal, without the web gui coming up, heres the options
| Option | What it does |
|---|---|
| `--fix` | Offer each available repair, asking before each one. |
| `--fix --yes` | Apply the low-risk repairs without asking. |
| `--fix --yes-all` | Also apply the repairs that normally need confirmation: rebuilding a damaged database, restoring the computer ID, trusting a folder in Git. |
| `--deep` | Slower and more thorough: full database integrity check, hashes of every key installation file, worktree sizes. |
| `--error "<message>"` | Explain an error message. |
| `--offline` | Make no network requests. |
| `--out <folder>` | Where to write the report. Default: the repair tool's folder. |
| `--json` | Also write the findings as JSON. |
| `--no-redact` | Keep your full paths, user name and e-mail address in the report. |
| `--hide-titles` | Leave chat titles out of the report. |
| `--state <file>` / `--install <folder>` | Use a different profile or installation. |
| `--restore <folder>` | Undo the repairs recorded in a backup folder. |

Exit code: `0` = no errors, `1` = errors found, `2` = the repair tool itself failed (which is BAAADD!!!!!)

it checks nearly everything you could need it to, 
anyways thats all
# happy freebuffing or whatever the kids say!
