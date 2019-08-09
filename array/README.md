# array

[![GoDoc](https://godoc.org/github.com/t94j0/array?status.svg)](https://godoc.org/github.com/t94j0/array)

Things that should probably be in the Go standard library

Array does mathematical array-related operations

## Why

I find myself doing things like checking if a value is in an array a lot. Since Go has the ability to do reflection very easily, I made this project to only write array utilities once.

The inspiration for this project comes from SQL database JOINs. Union isn't implemented for obvious reasons.

## Usage

See the examples for usage guides. Always remmeber to unpack your arrays so that you don't try to do array work with interfaces! The Go compiler should throw errors if you try.
