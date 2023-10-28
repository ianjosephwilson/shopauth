HOW TO RELEASE
++++++++++++++

- Make sure changes are commited in repo.
- Make sure changelog is up to date with unreleased changes since last release.
- `hatch version patch` or minor or major to bump version
- `hatch run bump-changelog` to replace Unreleased with actual version for latest change and insert new placeholder for new Unreleased changes
- commit version file change and changelog change via `git commit -m "Prepare for release." src/shopauth/__version__.py CHANGELOG.rst`
- `hatch run tag` to tag release revision with latest version
