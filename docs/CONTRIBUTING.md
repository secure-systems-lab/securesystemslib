# Instructions for contributors
Contribute by
[submitting pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)	
against the *main* (default) branch of this repository.

## Install for development
To install for local development 
[clone this repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository),
change into the project directory, and install with pip (using
[`venv`](https://docs.python.org/3/library/venv.html) is recommended).


```bash
python3 -m pip install -r requirements-dev.txt
```

*NOTE: Some dependencies may have system dependencies. If you face errors while
 installation, please consult with the documentation of the individual project,
 or [contact us](?tab=readme-ov-file#contact) for help.*

## Test
Run the test suite locally with [`tox`](https://tox.wiki/). Some tests, e.g.
for *sigstore* or *Cloud KMS* signing, are excluded by default (see 
[tox.ini](/tox.ini) for details). 

```bash
tox
```
