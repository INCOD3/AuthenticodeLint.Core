# VERSION:	0.1
# DESCRIPTION:	Surf-build for AuthenticodeLint
# AUTHOR:	Kevin Jones <kevin@vcsjones.com>
# COMMENTS:
#    Adapted from Paul Betts' gist
#    https://gist.github.com/paulcbetts/c3bb783cf45a13fd1e6e

FROM node:boron
MAINTAINER Kevin Jones <kevin@vcsjones.com>

ENV DEBIAN_FRONTEND noninteractive
# GITHUB_TOKEN ENV set in ECS. Don't put it in the docker file.

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils curl
RUN apt-get install -y --no-install-recommends \
	fakeroot \
	libunwind8 \
	gettext \
	build-essential \
	ca-certificates \
	git

# Install .NET Core
RUN curl -sSL -o dotnet.tar.gz https://go.microsoft.com/fwlink/?LinkID=835021 \
    && mkdir -p /opt/dotnet && tar zxf dotnet.tar.gz -C /opt/dotnet \
    && ln -s /opt/dotnet/dotnet /usr/local/bin

# Work Around: prime the nuget cache. Review when dotnet/cli#4919 is done. 
RUN mkdir -p /var/tmp/dotnet-prime \
    && cd /var/tmp/dotnet-prime && dotnet new && cd ~ \
    && rm -rf /var/tmp/dotnet-prime

# Install surf
RUN npm install -g surf-build@1.0.0-beta.15

CMD surf-run -r https://github.com/vcsjones/AuthenticodeLint.Core -- surf-build -n 'surf-netcore-1.1.0'
