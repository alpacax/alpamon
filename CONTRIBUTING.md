# Contributing to Alpamon

Thanks for helping improve Alpamon.

## Getting started

- Set up, build and test as described in [Development](README.md#development).
- Run the tests before you open a pull request, and describe how you verified the change.
- For a larger change, open an issue first so the approach can be agreed before you write it.

## How work is tracked and reviewed

The maintainers and their AI agents follow the same conventions on every issue and pull request in
this repository. A comment from a bot or an agent ends with one short line saying what it did and
how to undo it. This section is the rule that line refers to.

### Issues

- An assignee means someone is working on the issue. Its state is read from the assignee, a linked
  open pull request and GitHub's "blocked by" dependency. There is no status label.
- A comment may carry a hidden marker line (`<!-- alpacax:wt ... -->`) that records a wait or an
  expected finish date. Only markers from maintainers and bots count.
- `good first issue` and `help wanted` mark issues open to outside contributors.
- Report a security problem through a private GitHub security advisory, never in an issue.

### Pull requests

- Describe the change so it stands on its own: what changed, why, and how you verified it.
- WALL-D, our review bot, reviews pull requests from maintainers alongside people. Its commit
  status `walld/review` says where the review stands:

  | Status | Meaning |
  | --- | --- |
  | success, `reviewed <sha>: ...` | Approved at that commit |
  | failure | Findings to fix; they are posted as review threads |
  | pending, `reviewing:` or `queued:` | The review is running or waiting its turn |
  | pending, `awaiting-request:` | Comment `@alpacax-wall-d review` to request a review |
  | pending, `author-questions:` | Answer the questions in the review |
  | pending, `human-hold:` | A maintainer has to approve the current commit |

- The labels `needs-author-fix`, `needs-author-answer` and `needs-maintainer-approval` show whose
  turn it is. Only WALL-D sets them.
- A maintainer reviews pull requests from outside contributors.
