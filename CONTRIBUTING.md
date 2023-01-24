# Contributing

When planning for major code contributions to this repository,
please first discuss the changes you wish to make via issue, email,
or any other method with the owners of this repository beforehand.

Please note that we have a [code of conduct](CODEOFCONDUCT.md);
please follow it in all your interactions with the project.

## Pull Request Process

Please use the [Forking Workflow]
(https://www.atlassian.com/git/tutorials/comparing-workflows/forking-workflow)
and send us Pull Requests.

1. Update the [changelog](CHANGELOG.md)
   and as far as appropriate also the [README](README.md)
   with details of changes and updates of functions and interfaces.
2. Increase the version number in pom.xml
   to the new version that this Pull Request would represent.
   The versioning scheme we use is [SemVer](http://semver.org/).
3. You may merge a Pull Request in
   once you have the sign-off of two other developers,
   or if you do not have permission to do that,
   you may request the second reviewer to merge it for you.

## Code style formatting
The source code is formatted in accordance with the [Palantir style](https://github.com/palantir/palantir-java-format),
and a check is enforced via the CI pipeline.

The code can be auto-formatted locally by running `mvn spotless:apply`. Integration into some IDEs is available, for
example, there is a plugin for [IntelliJ](https://github.com/palantir/palantir-java-format#intellij-plugin).

While no plugin for Eclipse is available, an IDE-agnostic approach is to rely on git hooks. An example can be found in
`scripts/`, you can activate it by running `cp scripts/pre-commit .git/hooks`. The hook also works on Windows, if you
use `git-bash`, otherwise adjust the script accordingly.
