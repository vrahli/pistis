OMNeT++ configuration
---------------------

In Project -> Properties -> OMNeT++ -> Makemake (left menu)

    Build is set to 'Makemake'
    Source is set to 'Source Location'

Then in Build -> Makemake -> Options (right menu)

    Target type is set to 'Executable'
    Target name is set to 'default'
    Makefile Scope: only 'Deep' and not 'Recursive'

    Link contains these additional libraries
      gmp
      ssl
      crypto


Run the code
------------

You can run the code form omnet or from the commandline using
something like `./pistis -u Cmdenv -c smallpistis`. Other
configurations are available in the `omnetpp.ini` file


Authors
-------

- Jeremie Decouchant
- David Kozhaya
- Vincent Rahli
