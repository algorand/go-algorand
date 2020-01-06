## Jenkins Release Build

The `Jenkinsfile` uses the pipeline module to define its build stages.  Currently, they are:

1. create ec2 instance
1. setup ec2 instance
1. build
1. package
1. sign
1. upload
1. tag (TODO)
1. delete ec2 instance

The only thing that is not automated at this point is pre-setting the `gpg-agent` with the passphrase of the private key.  At the beginning of the `package` stage, Jenkins will pause and wait for the initiator of the build to do this and set up an SSH connection that will forward a Unix socket from the remote ec2 instance to the client, which in this case is most likely your laptop.

## Workflow

Take a look at the Jenkins build configuration.  This will set the build in motion by downloading the project from GitHub.

## Setting up the Forwarded Connection

To complete this step, you will need to do the following:

1. Download the `BuilderInstanceKey.pem` certificate from the appropriate Jenkins workspace and `chmod 400` on it or GPG will complain.  A subsequent step will assume that you moved this to the `$GOPATH/src/github/algorand/go-algorand/scripts/release` directory.
1. Get the instance name from AWS, i.e., https://us-west-1.console.aws.amazon.com/ec2/home?region=us-west-1#Instances:sort=instanceState
1. Change to the `$GOPATH/src/github/algorand/go-algorand/scripts/release` directory and execute `./socket.sh`, passing it the ec2 instance name that you just got from AWS:

        ./socket ec2-13-57-188-227.us-west-1.compute.amazonaws.com

1. At the prompt, input the GPG passphrase (**Don't do this in a public space!!**).
1. You should now be logged into the remote machine!
1. As a sanity, it is a good idea to sign some text as a test to make sure that the connection was set up properly.  Enter the following pipeline:

        echo foo | gpg -u rpm@algorand.com --clearsign

    If there are any errors or if you are prompted for the passphrase, log out and run the above command again.

1. Go back to Jenkins, hover over the build step that is currently paused, and click "Proceed".

This is all of the manual work that needs to be done.

**Note** that I'd currently like to fully automate this, but the only way to do that is to install the GPG keys on the Jenkins production maching.

> You may be wondering why it's necessary to automate the GPG bits.  Well, this is to circumvent the need to somehow get the private key onto the remote machine, which we definitely don't want to do.  See this explanation.

## Build Artifacts

The result of running this job will be to put the build artifacts and their detached signatures in the AWS `algorand-dev-deb-repo` bucket.  The location will depend on the type of artifact, of course.

In addition, the build logs will be placed into the AWS `algorand-devops-misc` S3 bucket under `buildlog`.

## Notes

All of the `aws ...` commands are now executed by Jenkins and are defined in the `Jenkinsfile`.  The reason for this is simple:  Jenkins already has the AWS auth credentials, and we don't want or need to be sending them anywhere else in the cloud.

## TODO

Create the git tag.
Upload the deb package via `aptly`.
Add ability to specify branch and/or channel.

