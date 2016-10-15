FROM centos:7.2.1511

RUN yum update -y

# Install OpenSSH server and SSH client
RUN yum install -y openssh-server openssh-clients sudo

# Install passwd
RUN yum install -y passwd
RUN yum install -y rsyslog

RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;

RUN systemctl enable sshd
RUN systemctl enable rsyslog

RUN /usr/bin/ssh-keygen -A -N ''

RUN mkdir -p /etc/vault-ssh-helper
ADD vault-ssh-helper-linux /usr/local/bin/vault-ssh-helper

ADD sshd /etc/pam.d/sshd

RUN useradd admin -G wheel
RUN echo 'admin:secret' | chpasswd
RUN useradd joe -G wheel
RUN echo 'joe:secret' | chpasswd

#RUN sed -ri 's/auth       substack     password-auth/#auth       substack     password-auth/g' /etc/pam.d/sshd
RUN sed -ri 's/account    required     pam_nologin.so/#account    required     pam_nologin.so/g' /etc/pam.d/sshd
#RUN sed -ri 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config

#RUN sed -i '1s/^/<added text> /' file
RUN sed -i '/#%PAM-1.0/a auth optional pam_unix.so not_set_pass use_first_pass nodelay' /etc/pam.d/sshd
RUN sed -i '/#%PAM-1.0/a auth sufficient pam_exec.so quiet expose_authtok log=/tmp/vaultssh.log /usr/local/bin/vault-ssh-helper -config=/etc/vault-ssh-helper/config.hcl' /etc/pam.d/sshd

#RUN mv /etc/pam.d/sshd /etc/pam.d/sshd.orig
#RUN echo "auth requisite pam_exec.so quiet expose_authtok log=/var/log/vaultssh.log /usr/local/bin/vault-ssh-helper -config=/etc/vault-ssh-helper/config.hcl" >> /etc/pam.d/sshd
#RUN echo "auth optional pam_unix.so no_set_pass use_first_pass nodelay" >> /etc/pam.d/sshd
#RUN sed -ri 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
#RUN sed -ri 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config

EXPOSE 22
ENTRYPOINT ["/sbin/init"]
