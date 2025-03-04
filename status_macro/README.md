# Status Macros

Status macros allow for convenient manipulation of `absl::Status` and
`absl::StatusOr` results without needing to manually check or unwrap them. They
allow for returning from an outer function on a non-Ok status, essentially
propagating any error that occurs. Assign can also allow for getting the value
from a StatusOr without explicitly de-referencing.

They also support adding to the returned status message, returning other things
beyond Status, and other manipulation.

<!-- copybara:strip_begin: TOTW and internal util reference -->

The original version is found in `//util/task/status_macros.h` and similar. This
version is based on `https://github.com/privacysandbox/data-plane-shared-libraries/blob/main/src/util/status_macro/status_macros.h`.
See also [go/totw/121](go/totw/121)

<!-- copybara:strip_end: TOTW and internal util reference -->

# Assign and return

The two main macros are defined in `status_macro/status_macros.h`.

`HATS_RETURN_IF_ERROR(expr)` evaluates an expression `expr` that returns
absl::Status. It propagates errors, where any non-Ok status is returned, and
otherwise continues. The expression can also take in `grpc::Status` or
`google::cloud::Status`, which get cast to `absl::Status`.

`HATS_ASSIGN_OR_RETURN(lhs, rexpr)` evaluates an expression `rexpr` that returns
a `absl::StatusOr<T>`. It propagates errors, where any non-Ok status is
returned. On Ok, `lhs` of type `T` gets assigned to the value within the
StatusOr. The left hand side can be a variable declaration (where it gets
initialized), or an existing variable. Note that this cannot cast other status
types, such as `google::cloud::StatusOr`.

As an example,

```c++
// Outer returns statusOr, or Status
Status_or<int> outer() {
  // Returning on a status
  HATS_RETURN_IF_ERROR(ReturnAbslStatus(args));
  HATS_RETURN_IF_ERROR(ReturnGrpcStatus(args));
  HATS_RETURN_IF_ERROR(ReturnCloudStatus(args));

  // Declaring and initializing x, so can be const and/or auto
  HATS_ASSIGN_OR_RETURN(const int x, MaybeGetValue(args));
  HATS_ASSIGN_OR_RETURN(auto x, MaybeGetValue(args));

  // Using pre-declared variable
  int y;
  HATS_ASSIGN_OR_RETURN(y, MaybeGetValue(args));
  // No de-reference needed from assigns
  int z = x + y;

  // Also dealing with pointers without move/de-reference
  HATS_ASSIGN_OR_RETURN(unique_ptr<Object> thing, f_return_statusor_object());
  thing->doStuff();
  f_act_on_Object(thing);

  // Can also assign to an expression with side effects
  MyProto data;
  HATS_ASSIGN_OR_RETURN(*data.mutable_str(), MaybeGetValue(args));

  return x + y;
}
```

# Output manipulation

The macros support for additional extensions. The most common uses are for
changing or adding to logging, and changing the return value.

These are defined in `status_macro/status_builder.h`. Specifically, these macros
provide a `StatusBuilder` that has a variety of methods for manipulation, and
which is implicitly convertible to `absl::Status` or `absl::StatusOr`.

For `HATS_RETURN_IF_ERROR`, the macro ends in a StatusBuilder, so the extensions
can be called directly. For example,
`HATS_RETURN_IF_ERROR(expr).Extension1().Extension2()`.

For `HATS_ASSIGN_OR_RETURN`, the macro has a 3-argument variant, where the third
argument is returned, with the variable `_` containing a StatusBuilder for
extension. For example `HATS_ASSIGN_OR_RETURN(int x, MaybeGetValue(),
_.Extension1().Extension2())`

## Message

The most common way we extend is with `PrependWith(string)`. For example,
`HATS_RETURN_IF_ERROR(expr).PrependWith("Error while doing F: ")` will return on
non-Ok with a status with a message of "Error while doing F: StatusText".

The default message extension is appended, which can be done with insertion as
`<<` as a stream. For example, `HATS_RETURN_IF_ERROR(f(x)) << " running on value
" << x` will error with a message of "StatusText running on value 7", for
example.

Logging levels can be set with e.g. LogWarning(), which also sends the message
to Warning on failure. For example, `HATS_ASSIGN_OR_RETURN(auto x, f(arg),
_.LogError() << " with arg " << arg)`.

Arbitrary functions can be passed in using `builder.With(...)`. Further details
and examples can be found in the documentation.

## Return

Sometimes the containing function returns something besides an `absl::Status` or
`absl::StatusOr`. Normally, the returned StatusBuilder can be implicitly cast to
these. There are several extensions that act as terminals, changing the return
type of `HATS_RETURN_IF_ERROR` or `HATS_ASSIGN_OR_RETURN` to match the return of
the outer function. Because they are terminal, they must be the last part of a
chain.

One of the most common use cases is returning from a `main` function with an
int. We provide `LogErrorAndExit()`, which on error logs the status message to
Error then returns 1.

Using `builder.With(fun)`, fun can be any function which takes in
`absl::Status`, and returns the same return type as the outer function. Constant
returns are provided in `status_macro/return.h`. Arbitrary returns can be done
with lambdas of the form `[](const absl::Status& status) { return f(status);}`,
or other functions. Note that the function must take in a `Status` as opposed to
`StatusBuilder`because StatusBuilders do logging when cast.

Some examples are as follows.

```c++
void f() {
  // Return Void macro, from return.h
  HATS_ASSIGN_OR_RETURN(int x, MaybeGetValue(arg),
                        _.With(status_macros::ReturnVoid));
}

grpc::Status g() {
  // Casting to GRPC status (included in status_macros.h)
  HATS_ASSIGN_OR_RETURN(int x, MaybeGetValue(arg),
                        _.With(status_macro::FromAbslStatus))
  // Lambda version of the above, for comparison
  HATS_ASSIGN_OR_RETURN(int x, MaybeGetValue(arg),
                        _.With([](const absl::Status& s) {
                          return status_macro::FromAbslStatus(s)
                        }))

  // Alternative to Return, using a lambda
  // Lambda Arg must be absl::Status to cast
  HATS_ASSIGN_OR_RETURN(
      int y, MaybeGetValue(arg),
      _.With([](const absl::Status& unused) { return grpc::kUnknown }))
}

int main(int argc, char* argv[]) {
  // Using Hats macro to Log to Error
  HATS_RETURN_IF_ERROR(RunMainFunction(flags))
      .PrependWith("Could not run: ")
      .LogErrorAndExit();

  // Using Return, from return.h
  HATS_RETURN_IF_ERROR(RunFunction2(flags)).With(status_macros::Return(1));
  // Using Lambda
  HATS_RETURN_IF_ERROR(RunFunction3(flags))
      .With([](const absl::Status& unused) { return 1; });
  return 0;
}
```

## Known issues

As noted, only HATS_RETURN_IF_ERROR is able to cast non-absl statuses to absl
statuses from its expression. Currently, HATS_ASSIGN_OR_RETURN does not support
expressions using non-absl statuses. Their return can still be cast as desired.

Status code changes are currently not supported, similar to
privacysandbox/data-plane-shared-libraries.

In a few places, for some reason only `ASSIGN(auto _, x)` is supported, but not
`RETURN(x.status())`. This seems to be when nested within another macro and/or
lambda.

`key-fetcher-wrapper.cc` can't have the macros due to issues with linkage from
rust bridge.

# Tests

We provide and use status macros for testing, found in
`status_macro/status_test_macros.h`. These are based on existing google3 macros,
adapted and extended for our use cases. By default they act on `absl:Status` and
`absl:StatusOr`, although a few macros with `_GRPC` take in the `grpc` version
of these statuses instead. Similarly to the above macros, these make it more
convenient around unwrapping and checking statuses, extended to remove the need
for `absl/status_matchers.h`.

At a high level, Expect continues the test on failure, while Assert stops the
test. Therefore Assert should be used on checks that stop the rest of the test
from running (such as no response, missing object), while Expect for invariants
being validated during the test (such as checking each value in a response).

## Ok

The most straightforward macros test if a Status/StatusOr are Ok.
`HATS_EXPECT_OK(expr)`, `HATS_ASSERT_OK(expr)`, `HATS_EXPECT_OK_GRPC(expr)`.

Similar to HATS_ASSIGN_OR_RETURN, `HATS_ASSERT_OK_AND_ASSIGN(lhs, rexpr)` checks
a StatusOr from `rexpr`, asserts it is Ok, and assigns it to the left hand side.
Similarly, this left hand side can be a new variable declaration or an existing
variable.

For testing the value of a StatusOr, there are `HATS_EXPECT_OK_AND_HOLDS(lhs,
value)` and `HATS_ASSERT_OK_AND_HOLDS(lhs, value)`, which asserts that the lhs
expression is both Ok, and the underlying value matches `value`. The right hand
side `value` can take testing pieces similar to that of `ExpectThat` from
`gtest/gtest.h`: literal value match, `StrEq`, `EqualsProto`, `AllOf`, etc.

## Status

The macros also support ensuring tests fail correctly, by checking that a
Status/StatusOr provides a given status. For just the status, there is
`HATS_EXPECT_STATUS(lhs, status)` and `HATS_EXPECT_STATUS_GRPC(lhs, status)`,
which take an absl::Status. Note that the GRPC status is mapped to its
corresponding absl status before being compared.

The message contents can also be checked via `HATS_EXPECT_STATUS_MESSAGE(lhs,
status, message)`. The message can take testing pieces from `gtest/gtest.h`,
such as an exact string or `HasSubstr`.

## Test examples

```c++
Test(...) {
  // Standard check Ok
  HATS_EXPECT_OK(f_status_ok());
  HATS_ASSERT_OK(f_status_ok());
  HATS_EXPECT_OK_GRPC(f_grpc_status_ok());

  // Assign to value if Ok
  HATS_ASSERT_OK_AND_ASSIGN(int x, ShouldGetValue());
  do_stuff_with(x);

  // Checking value of StatusOr
  HATS_EXPECT_OK_AND_HOLDS(ShouldBeOne(), 1);
  HATS_ASSERT_OK_AND_HOLDS(
      MaybeGetProto(), UnorderedElementsAre(EqualsProto(
                           R"pb(
                             name: "Foo" value: "Bar" key: "ThisIsASecret"
                           )pb")));

  // Checking status and message
  HATS_EXPECT_STATUS(BadStatus(), absl::kInternal);
  HATS_EXPECT_STATUS_GRPC(BadGrpcCall(args), absl::kInternal);
  HATS_EXPECT_STATUS_MESSAGE(BadArgument(args), absl::kInvalidArgument,
                             HasSubstr("Invalid Argument"));
}
```
