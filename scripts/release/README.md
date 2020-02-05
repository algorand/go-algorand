## Jenkins Release Build

The `Jenkinsfile` uses the pipeline module to define its build stages.  Currently, they are:

1. create ec2 instance
1. setup ec2 instance
1. build and package
1. test
1. sign
1. upload
1. delete ec2 instance

The only thing that is not automated is pre-setting the `gpg-agent` with the passphrase of the private key.  Build execution pauses at the beginning of the `sign` stage to allow for this manual process.  See below for details.

The build job is parameterized with sensible defaults except for the Git hash, which is blank and can vary for each job.

## Workflow

Take a look at the Jenkins build configuration.  This will set the build in motion by downloading the project from GitHub.

## Setting up the Forwarded Connection

To complete this step, you will need to do the following:

1. Download the `ReleaseBuildInstanceKey.pem` certificate from the appropriate Jenkins workspace and `chmod 400` on it or GPG will complain.  Move this to the `$GOPATH/src/github/algorand/go-algorand/scripts/release/controller` directory.
1. Get the instance name from AWS, i.e., `https://us-west-1.console.aws.amazon.com/ec2/home?region=us-west-1#Instances:sort=instanceState` or from the Jenkins workspace (`scripts/release/tmp/instance`).
1. Change to the `$GOPATH/src/github/algorand/go-algorand/scripts/release/controller` directory and execute `./socket.sh`, passing it the ec2 instance name:

        ./socket ec2-13-57-188-227.us-west-1.compute.amazonaws.com

1. At the prompt, input the GPG passphrase (**Don't do this in a public space!!**).
1. You should now be logged into the remote machine!
1. As a sanity, it is a good idea to sign some text as a test to make sure that the connection was set up properly.  Enter the following pipeline:

        echo foo | gpg -u rpm@algorand.com --clearsign

    Or, simply list the secret keys:

        gpg --list-secret-keys

    If nothing is listed, then logout and re-establish the connection.

    If there are any errors or if you are prompted for the passphrase, log out and run the above command again.

    Stay logged in!

1. Go back to Jenkins, hover over the build step that is currently paused, and click "Proceed".

This is all of the manual work that needs to be done.

> You may be wondering why it's necessary to automate the GPG bits.  Well, this is to circumvent the need to somehow get the private key onto the remote machine, which we definitely don't want to do.  See [this explanation].

## Build Artifacts

The result of running this job will be to put the build artifacts and their detached signatures in the AWS `algorand-dev-deb-repo` bucket.  The location will depend on the type of artifact, of course.

In addition, the build logs will be placed into the AWS `algorand-devops-misc` S3 bucket under `buildlog`.

## Notes

- All of the `aws ...` commands are now kicked off by Jenkins by shelling out to a script in the `stages` directory that is named after the relevant build stage.  These scripts in `stages` simply call the appropriate script in the `controller` directory.

- An ec2 instance is created and deleted by the `*_ec2_instance.sh` scripts in `release/`.  Any pertinent information, such as the instance name and security group ID, are stored in the sub-directory `release/tmp`.  This information is used by the shutdown script and then removed on a successful shutdown.

## Troublshooting

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

[this explanation]: https://stackoverflow.com/questions/30058030/how-to-use-gpg-signing-key-on-a-remote-server

