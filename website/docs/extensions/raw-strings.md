---
id: raw-strings
sidebar_label: Raw Strings
title: Raw Strings
---

# Server-Side Raw-String Extensions

Custom raw-string extensions allows adding new functions that operate on raw strings and registering them with Garnet. This registered function can then be invoked from any Garnet client and be executed on the Garnet server.

### Developing custom server side Raw-String Extensions

`CustomRawStringFunctions` is the base class for all custom raw-string functions. To develop a new one, this class has to be extended and then include the custom logic. There are six methods to be implemented in a new custom raw-string function:

- `GetInitialLength(ref RawStringInput input)`:\
    The `GetInitialLength` method returns the length of the initial expected length of value when populated by RMW using given input
- `GetLength(ReadOnlySpan<byte> value, ref RawStringInput input)`\
    The `GetLength` method returns the length of resulting value object when performing RMW modification of value using given input
- `InitialUpdater(ReadOnlySpan<byte> key, ref RawStringInput input, Span<byte> value, ref RespMemoryWriter writer, ref RMWInfo rmwInfo)`\
    The `InitialUpdater` method makes an initial update for RMW, given the key (`key`), the given input (`input`), the resulting value to be inserted (`value`), the writer to output the result of the `input` operation on `value` (`writer`) and the reference for the record info for this record (used for locking) (`rmwInfo`)
- `InPlaceUpdater(ReadOnlySpan<byte> key, ref RawStringInput input, Span<byte> value, ref int valueLength, ref RespMemoryWriter writer, ref RMWInfo rmwInfo)`\
    The `InPlaceUpdater` method performs an in-place update for RMW, given the key (`key`), the given input for computing the updated (`input`), the destination to be updated (`value`), the writer to output the result of the `input` operation on `value` (`writer`) and the location where
- `CopyUpdater(ReadOnlySpan<byte> key, ref RawStringInput input, ReadOnlySpan<byte> oldValue, Span<byte> newValue, ref RespMemoryWriter writer, ref RMWInfo rmwInfo)`\
    The `CopyUpdate` method performs a copy update for RMW, given the key (`key`), the given input for computing `newValue` from `oldValue` (`input`), the previous value to be copied/updated (`oldValue`), the destination to be updated (`newValue`), the writer copying `newValue` (`writer`) and the reference for the record info for this record (used for locking) (`rmwInfo`)
- `Reader(ReadOnlySpan<byte> key, ref RawStringInput input, ReadOnlySpan<byte> value, ref RespMemoryWriter writer, ref ReadInfo readInfo);`\
    The `Reader` method performs a record read, given the key for the record to be read (`key`), the user input for computing `writer` from `value` (`input`), the value for the record being read (`value`), the writer to output `value` (`writer`) and the reference for the record info for this record (used for locking) (`rmwInfo`)

There are two other optional methods to be implemented:
- `NeedInitialUpdate(ReadOnlySpan<byte> key, ref RawStringInput input, ref RespMemoryWriter writer)`\
    The `NeedInitialUpdate` determines whether copy-update for RMW should be invoked, given the key for the record (`key`), the user input to be used for computing the updated value (`value`) and the location where the result of the `input` operation is to be copied.\
    ***Note:*** If this method is not overridden, it returns `true` by default
- `NeedCopyUpdate(ReadOnlySpan<byte> key, ref RawStringInput input, ReadOnlySpan<byte> oldValue, ref RespMemoryWriter writer)`\
    The `NeedCopyUpdate` determines whether copy-update for RMW should be invoked, given the key for the record (`key`), the user input to be used for computing the updated value (`value`), the existing value that would be copied (`oldValue`) and the location where the result of the `input` operation on `oldValue` is to be copied.\
    ***Note:*** If this method is not overridden, it returns `true` by default

These are the helper methods for developing custom transactions.
- `GetNextArg(ref RawStringInput input, scoped ref int offset)`:\
    The `GetNextArg` method is used to retrieve the next argument from the input at the specified offset. It takes an ArgSlice parameter representing the input and a reference to an int offset. It returns an ArgSlice object representing the argument as a span. The method internally reads a pointer with a length header to extract the argument.
- `GetFirstArg(ref RawStringInput input)`:\
    The `GetFirseArg` method is used to retrieve the argument from the input at offset 0.

Registering the custom raw-string function is done on the server-side by calling the `NewCommand(string name, int numParams, CommandType type, CustomRawStringFunctions customFunctions, long expirationTicks = 0)` method on the Garnet server object's `RegisterAPI` object with its name, number of parameters, the CommandType (Read / ReadModifyWrite), an instance of the custom raw-string function class, and optionally the number of ticks for expiration.\
It is possible to register the custom raw-string function from the client-side as well (as an admin command, given that the code already resides on the server) by using the `REGISTERCS` command (see [Custom Commands](../dev/custom-commands.md)). 