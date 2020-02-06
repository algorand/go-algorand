## Shared Directory Structure Pattern

The `release/` directory will have a structure that looks like the following:

        release/
            build/
            test/
            prod/
            ...
            <scripts common to all builds {.sh,.md,Dockerfile,etc}>

Each subdirectory of `release/` represents a build pipeline and is self-contained.  In other words, it will have its own `Jenkinsfile` and whatever else it needs to perform its job.

The pattern is the following (all subdirecties of `release/` will follow this pattern):

        test/                       // Maps to "test" build pipeline.
            Jenkinsfile
            stage/
                setup/              // Maps to "setup" stage in Jenkinsfile.
                    run.sh
                    task.sh
                test/               // Maps to "test" stage in Jenkinsfile.
                    run.sh
                    task.sh
            deb/
                *.sh
                testDebian.exp
            rpm/
                *.sh

The `Jenkinsfile` is self-explanatory, so I'll gloss over it.  `stage/` will contain directories that directly map to a defined stage in the `Jenkinsfile`.  Each directory will contain two files:

1. run.sh
1. task.sh

`run.sh` will be the script called in the `Jenkinsfile` and contains any `aws cli` commands.  `task.sh` is then initiated by `run.sh` and contains the logic for the particular build stage.

The `rpm` and `deb` directories will contain scripts that are relevant to their respective packaging formats.

You may rely on this pattern, and this makes any troubleshooting relatively straightforward as you know where to find the code that executes a particular task due to setting reasonable expectations.

## Build Outcomes

This section briefly describes the expected outcomes of the current build pipelines.

1. build

    The result of running this job will be to put the build artifacts and their detached signatures in the staging `algorand-builds` bucket.

    In addition, the build logs will be placed into the AWS S3 bucket`algorand-builds/build-logs/channel`.

1. test

    Download the `deb` and `rpm` packages from staging and test.

1. prod

    Copy the build artifacts and their detached signatures from `algorand-builds` to the production `algorand-dev-deb-repo` bucket.  The [releases page] links to this location.

    In addition, local snapshots are used by Debian-based (`aptly`) and RHEL-based tooling to deploy the respective packages to `algorand-releases`.  These are the packages which can then by downloaded by `apt` and `yum`.

## Jenkins Release Build

Each `Jenkinsfile` uses the pipeline module to define its build stages.  Depending upon the pipeline, the stages will be different.

The build job is parameterized with sensible defaults except for the Git hash, which is blank and can vary for each job.

## Workflow

Take a look at each Jenkins build configuration in the Jenkins server UI.  This will set the build in motion by downloading the project from GitHub.

## Setting up the Forwarded Connection

The only thing that is not automated is pre-setting the `gpg-agent` with the passphrase of the private key.  Build execution pauses at the beginning of the `sign` stage of the `build` pipeline to allow for this manual process.

To complete this step, you will need to do the following:

1. Download the `ReleaseBuildInstanceKey.pem` certificate from the appropriate Jenkins workspace and `chmod 400` on it or GPG will complain.  Move this to the `$GOPATH/src/github/algorand/go-algorand/scripts/release/controller` directory.
1. Get the instance name from AWS, i.e., `https://us-west-1.console.aws.amazon.com/ec2/home?region=us-west-1#Instances:sort=instanceState` or from the Jenkins workspace (`scripts/release/tmp/instance`).
1. Change to the `$GOPATH/src/github/algorand/go-algorand/scripts/release/controller` directory and execute `./socket.sh`, passing it the ec2 instance name:

        ./socket ec2-13-57-188-227.us-west-1.compute.amazonaws.com

1. At the prompt, input the GPG passphrase (**Don't do this in a public space!!**).
1. You should now be logged into the remote machine!
1. As a sanity, it is a good idea to sign some text as a test to make sure that the connection was set up properly.  Enter the following pipeline:

        echo foo | gpg -u rpm@algorand.com --clearsign

    If there are any errors or if you are prompted for the passphrase, log out and run the above command again.

    Stay logged in!

1. Go back to Jenkins, hover over the build step that is currently paused, and click "Proceed".

This is all of the manual work that needs to be done.

> You may be wondering why it's necessary to automate the GPG bits.  Well, this is to circumvent the need to somehow get the private key onto the remote machine, which we definitely don't want to do.  See [this explanation].

## Notes

- All of the `aws ...` commands are now kicked off by Jenkins by shelling out to a script in the `stages` directory that is named after the relevant build stage.

- An ec2 instance is created and deleted by the `*_ec2_instance.sh` scripts in `release/`.  Any pertinent information, such as the instance name and security group ID, are stored in the sub-directory `release/tmp`.  This information is used by the shutdown script and then removed on a successful shutdown.

## Troubleshooting

If testing on a server, you will get bad creds errors if your system's clock is off by even a couple minutes.  Examples like the following will alert you to the problem:

```
An error occurred (AuthFailure) when calling the CreateSecurityGroup operation: AWS was not able to validate the provided access credentials
```

If you're on a debian-based system, this **should** work:

    # https://github.com/mitchellh/vagrant-aws/issues/372#issuecomment-87429450
    $ sudo apt-get install ntpdate
    $ sudo ntpdate ntp.ubuntu.com

You may also try reconfiguring your `tzdata` package:

    $ sudo dpkg-reconfigure tzdata

---

If you are getting errors such as the following, it means that `gpg` has not been able to connect to the `gpg-agent` and therefore is attempting to get the passphrase from the user by raising a pinentry program:

    echo wat | gpg -u dev@algorand.com --clearsign
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    wat
    gpg: signing failed: Inappropriate ioctl for device
    gpg: [stdin]: clear-sign failed: Inappropriate ioctl for device

The failure is saying that there is no terminal attached to the session and so no program can be raised.

> Note that it is not necessary to set a terminal to successfully enable remote signing!  Do not attempt to "fix" this by setting the `GPG_TTY` environment variable!!

[this explanation]: https://stackoverflow.com/questions/30058030/how-to-use-gpg-signing-key-on-a-remote-server
[releases page]: https://releases.algorand.com/

