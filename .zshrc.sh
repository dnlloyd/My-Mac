ZSH_DISABLE_COMPFIX="true"

# Path to your oh-my-zsh installation.
export ZSH="${HOME}/.oh-my-zsh"

# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/ohmyzsh/ohmyzsh/wiki/Themes
# ZSH_THEME="robbyrussell"
ZSH_THEME=""

# Set list of themes to pick from when loading at random
# Setting this variable when ZSH_THEME=random will cause zsh to load
# a theme from this variable instead of looking in $ZSH/themes/
# If set to an empty array, this variable will have no effect.
# ZSH_THEME_RANDOM_CANDIDATES=( "robbyrussell" "agnoster" )

# Uncomment the following line if you want to change the command execution time
# stamp shown in the history command output.
# You can set one of the optional three formats:
# "mm/dd/yyyy"|"dd.mm.yyyy"|"yyyy-mm-dd"
# or set a custom format using the strftime function format specifications,
# see 'man strftime' for details.
HIST_STAMPS="mm/dd/yyyy"
setopt EXTENDED_HISTORY
setopt SHARE_HISTORY
setopt APPEND_HISTORY

# Which plugins would you like to load?
# Standard plugins can be found in $ZSH/plugins/
# Custom plugins may be added to $ZSH_CUSTOM/plugins/
# Example format: plugins=(rails git textmate ruby lighthouse)
# Add wisely, as too many plugins slow down shell startup.
plugins=(git)

source $ZSH/oh-my-zsh.sh
unsetopt nomatch
set -o vi


# Auto completion
autoload bashcompinit && bashcompinit
autoload -Uz compinit && compinit
compinit

# Compilation flags
# export ARCHFLAGS="-arch x86_64"

####################################### Prompt ###########################################
# Load version control information
autoload -Uz vcs_info
precmd() { vcs_info }

# Format the vcs_info_msg_0_ variable (for git prompt)
zstyle ':vcs_info:git:*' formats '[%b]'
setopt PROMPT_SUBST
NEWLINE=$'\n'

PS1='%F{green}%~ %F{cyan}${vcs_info_msg_0_}%{$reset_color%}${NEWLINE}%F{green}[%D{%H:%M:%S}]#%{$reset_color%} '

####################################### Environment Variables ##########################################
export EDITOR=vim

# Git Orgs
export GITHUB_FOG="github/FoghornConsulting"
export GITHUB_ME="github/dnlloyd"

# Git Repos
export GITHUB_MY_MAC="${GITHUB_ME}/My-Mac"
export SCRIPTS="${GITHUB_MY_MAC}/scripts"

# MySQL
# export PATH="$PATH:/usr/local/opt/mysql-client/bin"
# export PATH=$PATH:/Applications/MySQLWorkbench.app/Contents/MacOS

# export AWS_PROFILE="XXX"

# Set up aws-shell
# source ${GITHUB_MY_MAC}/aws/aws-shell-utils/env-variables.sh --source-only
# USE_AWS_PROMPT=0
# source ${GITHUB_MY_MAC}/aws/aws-shell-utils/functions.sh --source-only

########################################### Language Support ###########################################
# RBENV
eval "$(rbenv init - zsh)"

# PYENV
eval "$(pyenv init -)"
# export PYENV_VERSION="3.9.2"

# SDKMAN
# export SDKMAN_DIR="${HOME}/.sdkman"
# [[ -s "${HOME}/.sdkman/bin/sdkman-init.sh" ]] && source "${HOME}/.sdkman/bin/sdkman-init.sh"

# Google Cloud SDK
# The next line updates PATH for the Google Cloud SDK.
# if [ -f "${HOME}/pinecone/google-cloud-sdk/path.zsh.inc" ]; then source "${HOME}/pinecone/google-cloud-sdk/path.zsh.inc"; fi

# The next line enables shell command completion for gcloud.
# if [ -f "${HOME}/pinecone/google-cloud-sdk/completion.zsh.inc" ]; then source "${HOME}/pinecone/google-cloud-sdk/completion.zsh.inc"; fi

# Added by Nix installer
# if [ -e $HOME/.nix-profile/etc/profile.d/nix.sh ]; then . $HOME/.nix-profile/etc/profile.d/nix.sh; fi

# JENV (https://github.com/jenv/jenv)
# eval export PATH="/Users/dan/.jenv/shims:${PATH}"
# export JENV_SHELL=zsh
# export JENV_LOADED=1
# unset JAVA_HOME
# source '/usr/local/Cellar/jenv/0.5.4/libexec/libexec/../completions/jenv.zsh'
# jenv rehash 2>/dev/null
# jenv refresh-plugins
# jenv() {
#   typeset command
#   command="$1"
#   if [ "$#" -gt 0 ]; then
#     shift
#   fi

#   case "$command" in
#   enable-plugin|rehash|shell|shell-options)
#     eval `jenv "sh-$command" "$@"`;;
#   *)
#     command jenv "$command" "$@";;
#   esac
# }

############################################# AWS Stuff ##############################################

function awsip () {
  # AWS IP lookup
  # Usage: awsip <IP address>
  # Ex: awsip 10.32.123.123

  aws ec2 describe-network-interfaces --filters "Name=addresses.private-ip-address,Values=$1" --query NetworkInterfaces[*].[Description,NetworkInterfaceId,SubnetId,PrivateIpAddress,AvailabilityZone] --output table --region $AWS_REGION
}

function listawspubips () {
  # AWS List public IPs
  # Usage: listawspubips

  aws ec2 describe-network-interfaces --query NetworkInterfaces[*].[Description,Association.PublicIp] --output table --region $AWS_REGION
}

function shivalb () {
  for alb in $( aws elbv2 describe-load-balancers --query "LoadBalancers[*].LoadBalancerName" --output table --region $AWS_REGION |grep -i $1 |awk '{print $2}' )
  do
    echo ''
    type=`aws elbv2 describe-load-balancers --name $alb --query "LoadBalancers[*].Scheme" --output text --region $AWS_REGION`
    echo "${bold=$(tput bold)}$alb${NORMAL} ($type)"
    aws ec2 describe-network-interfaces --query "NetworkInterfaces[*].{ID:NetworkInterfaceId,Description:Description,PrivateIpAddress:PrivateIpAddress}" --filters "Name=description,Values=ELB app/$alb/*" --output table --region $AWS_REGION
  done
}

function get_alb_certs () {
  certs=()
  for lb_arn in $( aws elbv2 describe-load-balancers --query "LoadBalancers[*].LoadBalancerArn" --output text --region $AWS_REGION )
  do 
    lb_name=`echo ${lb_arn} | sed -e 's/arn:aws:elasticloadbalancing:.*:loadbalancer\/app\///g' |awk -F'\/' '{print $1}'`
    echo "${BOLD}${lb_name}${NC}"
    echo "--- ${lb_arn} ---"

    for list_arn in $( aws elbv2 describe-listeners --load-balancer-arn $lb_arn --query "Listeners[*].ListenerArn" --output text --region $AWS_REGION )
    do
      echo "Listener ARN: ${list_arn}"
      cmd="aws elbv2 describe-listener-certificates --listener-arn ${list_arn} --region ${AWS_REGION} --query 'Certificates[*].CertificateArn' --output text"
      for cert_arn in $( zsh -c $cmd )
      do
        certs+=($cert_arn)
        if [[ "${cert_arn}" == "None" ]]
        then
          echo " - No certificate"
        else
          aws acm describe-certificate --certificate-arn $cert_arn --query "Certificate.[DomainName,Subject,Issuer]" --output table --region $AWS_REGION
        fi
      done
      echo ''
    done
  done

  certs_final=()
  for cert_arn in ${certs[@]}
  do
    if [[ "${cert_arn}" != "None"  ]]
    then
      certs_final+=($cert_arn)
    fi
  done
}

function cert_lookup () {
  # aws acm describe-certificate --certificate-arn $1 --query "Certificate.[DomainName,Subject,Issuer,InUseBy,SubjectAlternativeNames,Serial,NotAfter]" --region $AWS_REGION
  aws acm describe-certificate --certificate-arn $1 --query "Certificate.{Domain:DomainName,Subject:Subject,Issuer:Issuer,InUseBy:InUseBy,Serial:Serial,NotAfter:NotAfter}" --region $AWS_REGION --output table
}

function get_all_certs () {
  for cert_arn in $( aws acm list-certificates --query "CertificateSummaryList[*].CertificateArn" --output text --region $AWS_REGION )
  do
    cert_lookup $cert_arn
    echo ''
  done
}

function shivdns () {
  for zone in $( aws route53 list-hosted-zones --query "HostedZones[*].Name" --output table --region $AWS_REGION |grep -i $1 |awk '{print $2}' )
  do
    echo ''
    id=`aws route53 list-hosted-zones --query "HostedZones[*].[Name,Id]" --output table --region $AWS_REGION |grep $zone |awk '{print $4}'`
    echo "${bold=$(tput bold)}$zone${NORMAL}"
    aws route53 list-resource-record-sets --hosted-zone-id $id --output table --region $AWS_REGION
    echo ''
  done
}

function listgas () {
  aws globalaccelerator list-accelerators --region us-west-2 --query "Accelerators[*].[Name,AcceleratorArn]" --output table
}

# Optional: Check for valid AWS token (From AWS Shell Utils)
# awscheck

function listbucketsencr () {
  for bucket_name in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do
      encryption=`aws s3api get-bucket-encryption --bucket ${bucket_name} --query ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault --output text 2>/dev/null`

      for bool in $( aws s3api get-bucket-policy --bucket ${bucket_name} --output text --query Policy | jq '.Statement[].Condition.Bool."aws:SecureTransport"' )
      do 
        if [[ "${bool}" == "false"  ]]
        then
          sid=`aws s3api get-bucket-policy --bucket ${bucket_name} --output text --query Policy | jq '.Statement[].Sid'`
          action=`aws s3api get-bucket-policy --bucket ${bucket_name} --output text --query Policy | jq '.Statement[].Action'`
          effect=`aws s3api get-bucket-policy --bucket ${bucket_name} --output text --query Policy | jq '.Statement[].Effect'`
          principal=`aws s3api get-bucket-policy --bucket ${bucket_name} --output text --query Policy | jq '.Statement[].Principal'`

          echo "--- ${bucket_name} ---"
          echo $sid
          echo $action
          echo $effect
          echo $principal
        fi
      done

      policies_conditional_booleans=`aws s3api get-bucket-policy --bucket ${bucket_name} --output text --query Policy | jq '.Statement[].Condition.Bool' 2>/dev/null`
      echo "${bucket_name}: ${encryption}"
  done
}

# AWS CLI
# Override AWS CLI version 1 installed at ${HOME}/.pyenv/shims/aws
# alias aws="/usr/local/bin/aws"
alias aws_completer="/usr/local/bin/aws_completer"
complete -C '/usr/local/bin/aws_completer' aws

########################################### Aliases ###########################################
# AWS Aliases 
alias awsunset='unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN'

# Personal AWS SSH
alias sshme="ssh -l ec2-user -i ${HOME}/aws_keys/aws-personal.pem -o \"StrictHostKeyChecking no\""

# Search
alias notes="${SCRIPTS}/notes.sh"
alias docs="${SCRIPTS}/docs.sh"

# alias knifessh='/opt/chefdk/embedded/bin/knife ssh'
alias kraken='open -na "GitKraken" --args -p "$(git rev-parse --show-toplevel)"'
alias be='bundle exec'
alias syntax="${SCRIPTS}/syntax_check.sh"

alias tf='terraform'
# alias tfenv="${SCRIPTS_BETA}/tfenv.sh"
alias gitfog="cd ${GITHUB_FOG}"
alias gitdan="cd ${GITHUB_ME}"
alias reshell="source ~/.zshrc"
alias gituseraudit="ruby ${SCRIPTS}/github/github_user_audit.rb"

function lastcmd () {
  # Search for my last command
  history | grep $1 | tail -1
}

function avnice () {
  for pid in $( pgrep -f "wdavdaemon" )
  do
    sudo ls > /dev/null
    echo "${BOLD}MS Defender PID: ${pid}${NC}"
    current_niceness=`ps -o ni $pid |grep -v ^NI`
    echo "Current nice value: ${current_niceness}"

    sudo renice 20 -p $pid

    current_niceness=`ps -o ni $pid |grep -v ^NI`
    echo "New nice value: ${current_niceness}"
    echo ''
  done
}

# export PATH=$PATH:/Users/dan/apache-maven-3.8.4/bin
