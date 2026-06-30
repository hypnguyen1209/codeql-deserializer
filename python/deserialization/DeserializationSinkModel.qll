/**
 * Deserialization sink & flow model for Python.
 *
 * Single extension point of the pack. Re-exports the official
 * `codeql/python-all` deserialization model (pickle, cPickle, marshal, PyYAML,
 * shelve, dill, jsonpickle, ...). Add new sinks via the `Decoding::Range`
 * modeling API (see docs/extending.md) and every query below will pick them up.
 */

import python
import semmle.python.Concepts
import semmle.python.security.dataflow.UnsafeDeserializationQuery

/** A Python deserialization sink: an insecure decoding that may execute its input (CWE-502). */
class PythonDeserializationSink extends Decoding {
  PythonDeserializationSink() { this.mayExecuteInput() }

  /** The decoded format, e.g. "pickle", "marshal", "YAML". */
  string getSinkFormat() { result = this.getFormat() }
}

/** Global taint flow from active threat-model sources (remote/user input)
 *  to deserialization sinks. Provided by `codeql/python-all`. */
module PythonDeserializationFlow = UnsafeDeserializationFlow;
