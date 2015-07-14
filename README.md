# IRMA MNO common

This library contains the java classes used in the communication protocol between the
card emulator application and the MNO server.

## Prerequisites

This library has the following dependencies.  All these dependencies will be automatically downloaded by gradle when building or installing the library.

Internal dependencies:

 * [credentials/scuba](https://github.com/credentials/scuba/), scuba_smartcards The Scuba smart-card abstraction layer

External dependencies:

 * [Apache Commons Codec](https://commons.apache.org/proper/commons-codec/)
 * [Google GSON](https://code.google.com/p/google-gson/)

## Building using Gradle (recommended)

When you are using the Gradle build system, just run

    gradle install

to install the library to your local repository. Alternatively, you can run

    gradle build

to just build the library.

## Eclipse development files

You can run

    gradle eclipse

to create the required files for importing the project into Eclipse.
