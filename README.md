# Patchstack Firewall Engine #

This repository contains the firewall engine of Patchstack.
It can be implemented inside of other content management systems to provide firewall functionality.

## How do I get set up? ##

Due to library limitations and the way the firewall engine works, a few manual interactions are required. Since the firewall engine depends on the opis/closure and laravel/serializable-closure packages which both require different PHP versions, sticking to one PHP version is tricky.

Therefore, in order to use this package, these libraries must exist in the following locations:
* opis/closure at /vendor/closure/
* laravel/serializable-closure at /vendor/serializable-closure/

## To-Do List ##
- ⬜️ Unit tests
- ⬜️ Test on many different environments and combinations with other plugins
- ⬜️ Attach PHP CS Fixer
- ✅ First initial concept and implementation

## Who do I talk to? ##

* dave.jong@patchstack.com