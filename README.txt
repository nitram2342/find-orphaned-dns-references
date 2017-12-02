The script find-orphaned-dns-references.py is a helper script that
supports "auditors" in finding orphanded DNS references like CNAMES
or MX records pointing to third-party domains that have been forgotten
and are not registered anymore.

The idea for writing this script is based on a talk by Daniel
Stirnimann titled "Breaking security controls using domain
hijacking" [0] held at the BSides Zurich. 

[0] https://bsideszh.ch/wp-content/uploads/2017/10/bsideszh-Daniel.pdf

