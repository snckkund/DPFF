FROM jenkins/jenkins:lts

# Skip setup wizard
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

# Install plugins
USER root
RUN jenkins-plugin-cli --plugins \
    workflow-aggregator \
    git \
    pipeline-stage-view \
    credentials-binding \
    docker-workflow \
    configuration-as-code

# Install Docker CLI (so Jenkins can build/push images)
RUN apt-get update && \
    apt-get install -y docker.io curl nodejs npm && \
    rm -rf /var/lib/apt/lists/*

# Add jenkins user to docker group
RUN usermod -aG docker jenkins

USER jenkins
