# Patchstack Firewall Engine #

This repository contains the firewall engine of Patchstack.
It can be implemented inside of other content management systems to provide firewall functionality.

## How do I get set up? ##

Since the firewall engine depends on the opis/closure and laravel/serializable-closure packages which both require different PHP versions, sticking to one PHP version is tricky.

Therefore, in order to use this package, the composer install command must be executed with the --ignore-platform-reqs flag:

`composer install --ignore-platform-reqs`

## To-Do List ##
- ✅ First initial concept and implementation
- ⬜️ Unit tests
- ⬜️ Test on many different environments and combinations with other plugins
- ⬜️ Attach PHP CS Fixer

## Who do I talk to? ##

* dave.jong@patchstack.com