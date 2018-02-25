Windows compilation
###################

Introduction
============

This procedure has been successfully tested with the following configuration:

*   Windows 7 with all updates applied
*   Visual Studio Community 2017
*   libtommath ("develop" branch)
*   libtomcrypt ("v1.18.1" release)
*   php_tomcrypt ("develop" branch)
*   PHP 7.2.2


Prerequisites
=============

.. : Note: links to the various prerequisites are available at the end of this file. : ..

Install Visual Studio
---------------------

First, download and install Visual Studio 2017.
The `Visual Studio Community 2017`_ edition is sufficient.

During the installation, make sure the "Desktop development with C++" component
is selected, as well as the "Windows 8.1 SDK and UCRT SDK" optional sub-component.

..  note::

    The web installer uses modern algorithm to sign its manifest.
    Windows 7 (and probably others) did not come with the support for such
    algorithms when released. However, Microsoft has provided updates that
    add support for such algorithms.

    If you get an error about the verification of the manifest's signature
    during the installation, make sure you have applied the latest updates
    available for your version of Windows.


Compile dependencies
--------------------

Download the latest ZIP releases for `libtommath`_ and `libtomcrypt`_.

..  note::

    For the time being, no release of ``libtommath`` supports the latest versions
    of Visual Studio. Therefore, we recommend that you download the ZIP archive
    for the project's ``develop`` branch instead.

Extract the archives to ``C:\``.

Launch Visual Studio and select ``File`` > ``Open`` > ``Project/Solution...``.
Navigate to libtomcrypt's folder and select ``libtomcrypt_VS2008.vcproj``.
Visual Studio will inform you that the file is meant for an earlier version
of Visual Studio and need to be upgraded. Click ``OK``.
It will also complain that the code may have been downloaded from an untrusted
source and will ask you to confirm whether you really want to import the project.
Click "OK" to confirm.

Now, right-click on the solution and ``Add`` > ``Existing Project...``.
Navigate to libtommath's folder and select ``libtommath_VS2008.vcproj``.
Like before, you will need to upgrade the project's file and confirm that
you want to import it in the solution. Click "OK" at each step to confirm.

Right-click on the ``libtomcrypt`` project and select
``Build Dependencies`` > ``Project Dependencies``.
In the popup dialog, make sure ``libtommath`` is checked under "Depends on:".
Confirm by clicking on "OK".

Right-click on the ``libtomcrypt`` project and select ``Properties``.
In the popup dialog, navigate to ``Configuration Properties`` > ``C++`` > ``General``,
select the value for the ``Additional Include Directories`` option,
and choose ``<Edit...>``.
Edit the line that reads ``..\libtommath`` and make it point to libtommath's
directory. Eg. ``C:\libtommath-develop\``.
Confirm the changes by clicking on "OK" until you get back to the main window.

In the topside menu, select ``Build`` > ``Configuration Manager...``.
Select ``Release`` from the ``Active solution configuration`` dropdown and
``<New ...>`` from the ``Active solution platform`` dropdown.
In the new dialog, select ``x64`` in the ``Type or select the new platform:``
dropdown, select ``Win32`` in ``Copy settings from:``, and make sure the
``Create new project platforms`` checkbox is unchecked.
Confirm by clicking "OK".

Make sure both projects are configured so as to be built, then close
the configuration manager.

Right-click on the ``libtommath`` project and select ``Properties``.
Make sure that the ``Configuration:`` is set to ``Active(Release)``
and the ``Platform`` is set to ``Active(x64)``.
Now, go to ``Configuration Properties`` > ``C++`` > ``Preprocessor``.
Click on the value for the ``Preprocessor Definitions`` option and select
``<Edit...>`` from the dropdown. Add ``MP_32BIT`` to the list of existing
definitions and confirm the changes by clicking "OK" until you get back
to the main window.

Build all the projects by clicking ``Build`` > ``Build Solution``
or by pressing ``Ctrl+Shift+B``.


Create a PHP build environment
------------------------------

Follow the instructions on https://wiki.php.net/internals/windows/stepbystepbuild_sdk_2
to setup the build directory. We recommend that you put the SDK at the root of
a volume (eg. ``C:\php-sdk-2.1.1``

..  note::

    You do not need to compile PHP. You only need a build directory ready
    to compile the extension.


Compile the extension
=====================

Follow the instructions on building a PECL extension from
https://wiki.php.net/internals/windows/stepbystepbuild_sdk_2
upto (and including) the ``buildconf`` command.

Now, run configure with the following options:

``configure --disable-all --enable-cli --with-tomcrypt=shared --with-extra-includes=C:\libtomcrypt-1.18.1\src\headers --with-extra-libs=C:\libtomcrypt-1.18.1\MSVC_x64_Release``

(adapt the paths depending on your installation)

Finally, run ``nmake`` to actually compile the code.

That's it, the extension is now available (look for "php_tomcrypt.dll"
under ``C:\php-sdk-2.1.1\phpdev\vc15\x64\php-7.2.2-src\x64\Release_TS``).



..  _`Visual Studio Community 2017`:
    https://www.visualstudio.com/downloads/1

..  _`libtommath`:
    https://github.com/libtom/libtommath

..  _`libtomcrypt`:
    https://github.com/libtom/libtomcrypt
