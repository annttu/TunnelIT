#!/usr/bin/env python3

import subprocess
import sys
import time
import os.path
import logging
import yaml
import tempfile

logger = logging.getLogger("tunnelIT")

OPENFORTIVPN = "/opt/homebrew/bin/openfortivpn"
PING = "/sbin/ping"

CONFIG_BASEPATH = os.path.expanduser("~/.tunnelit")

ADD = "add"
DELETE = "delete"


def check_interface_exists(name):
    result = subprocess.run(["/sbin/ifconfig", name])
    return result.returncode == 0


def ip_route(action, network, interface=None, gateway=None):
    args = ["/sbin/route", action, "-net", network]
    if interface:
        args.append("-iface")
        args.append(interface)
    if gateway:
        args.append(gateway)
    result = subprocess.run(args)
    return result.returncode == 0


def log_stdout(stdout):
    if not stdout:
        return
    for row in stdout.decode("utf-8").splitlines():
        logger.info(row)


def log_stderr(stderr):
    if not stderr:
        return
    for row in stderr.decode("utf-8").splitlines():
        logger.error(row)


def log_process(stdout, stderr):
    if stdout:
        log_stdout(stdout)
    if stderr:
        log_stderr(stderr)


def load_password(username, itemname):
    result = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", username, "-l", itemname, "-w"],
                            check=True, capture_output=True)
    return result.stdout.decode("utf-8").strip()


class GenericTunnel(object):
    def __init__(self, config):
        self.config = config
        self.interface = None

    def start_tunnel(self, otp=None):
        pass

    def stop_tunnel(self):
        pass

    def check_tunnel(self):
        return False


class FortiVPNTunnel(GenericTunnel):
    def __init__(self, config):
        super().__init__(config)
        self._tunnel = None
        self.interface = None
        self.keepalive_pid = None

    def find_free_interface(self) -> str:
        """
        Find next free ppp interface, openfortivpn uses next free ppp interface for tunnel
        On macOS pppd don't allow setting ppp interface manually.

        TODO: this method is not thread safe in any way

        :return: next free ppp interface name
        """
        idx = 0
        for i in range(0, 100):
            if not check_interface_exists(f"ppp{idx}"):
                break
            idx += 1
        else:
            raise RuntimeError("Failed to find free ppp interface")
        return f"ppp{idx}"

    def start_tunnel(self, otp=None) -> bool:
        """
        Start tunnel process
        process is forked to background
        :param otp: Optional OTP token
        :return: Process status
        """

        self.interface = self.find_free_interface()

        params = [OPENFORTIVPN, "--set-routes=0", "--set-dns=0"]
        password = None
        if self.config.get("config_file"):
            params.append("-c")
            params.append(os.path.expanduser(self.config.get("config_file")))
        if otp:
            params.append("-o")
            params.append(otp)
        if self.config.get("password_item") and self.config.get("password_username"):
            password = load_password(self.config.get("password_username"), self.config.get("password_item"))
        logger.debug(f"Executing {' '.join(params)}")

        self._tunnel = subprocess.Popen(params, stdin=subprocess.PIPE)  # , stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2)

        try:
            if password:
                logger.debug(f"Pasting password to stdin")
                self._tunnel.stdin.write(password.encode("utf-8") + b"\n")
                self._tunnel.stdin.flush()
                # self._tunnel.stdin.close()

            for i in range(100):
                if self.check_tunnel_started():
                    logger.info("Tunnel is up and running")
                    break
                time.sleep(1)

            if self.config.get("keepalive_target"):
                self.keepalive_pid = subprocess.Popen([PING, "-qi", "10", self.config.get("keepalive_target")])
            return self.check_tunnel()
        except Exception as exc:
            self.stop_tunnel()
            raise

    def check_tunnel_started(self) -> bool:
        return check_interface_exists(self.interface)

    def check_tunnel(self) -> bool:
        """
        Return if tunnel status is OK
        :return: boolean
        """
        if not self._tunnel or self._tunnel.returncode is not None:
            return False
        try:
            stdout, stderr = self._tunnel.communicate(timeout=1)
            log_process(stdout, stderr)
        except subprocess.TimeoutExpired:
            return True
        return self._tunnel.poll() is None

    def stop_tunnel(self) -> bool:
        logger.info("killing tunnel")
        if self.keepalive_pid:
            self.keepalive_pid.terminate()
            try:
                self.keepalive_pid.wait(5)
            except subprocess.TimeoutExpired:
                pass
        if self._tunnel and self._tunnel.poll() is None:
            self._tunnel.terminate()
            try:
                stdout, stderr = self._tunnel.communicate(timeout=5)
                log_process(stdout, stderr)
            except subprocess.TimeoutExpired:
                logger.error("Failed to terminate vpn process, trying to kill")
                self._tunnel.kill()
                try:
                    stdout, stderr = self._tunnel.communicate(timeout=5)
                    log_process(stdout, stderr)
                except subprocess.TimeoutExpired:
                    logger.error("Failed to kill vpn process")
                    return False
        return True


class TunnelIT(object):
    def __init__(self, name):
        self.name = name
        self.config = None

    def load_config(self):
        name = os.path.basename(f"{self.name}.yaml")
        with open(os.path.join(CONFIG_BASEPATH, name), 'r') as f:
            config = yaml.load(f, yaml.SafeLoader)
        assert "type" in config
        self.config = config

    def set_routes(self, interface):
        for route in self.config.get("routes", []):
            logger.info(f"Setting route {route} via {interface}")
            if not ip_route(ADD, route, interface=interface):
                logger.error(f"Failed to set route {route}")

    def set_nameservers(self):
        for domain, nameservers in self.config.get("domains", {}).items():
            logger.info(f"Setting domain {domain} nameserver(s) to {','.join(nameservers)}")
            handle, path = tempfile.mkstemp(dir="/etc/resolver", suffix=".tmp_")
            for nameserver in nameservers:
                os.write(handle, f"nameserver {nameserver}\n".encode("utf-8"))
            os.close(handle)
            os.rename(path, f"/etc/resolver/{domain}")
            os.chmod(f"/etc/resolver/{domain}", 0o0644)
            # logger.info(f"Failed to set nameservers for {domain}")

    def unset_routes(self):
        for route in self.config.get("routes"):
            logger.info(f"Removing route {route}")
            if not ip_route(DELETE, route):
               logger.error(f"Failed to unset route {route}")

    def unset_nameservers(self):
        for domain, nameservers in self.config.get("domains", {}).items():
            filename = f"/etc/resolver/{domain}"
            try:
                if os.path.isfile(filename):
                    os.remove(filename)
            except FileNotFoundError:
                pass

    def run(self, otp):

        # Load config
        self.load_config()
        # Execute tunnel
        if self.config.get("type") == "fortivpn":
            tunnel = FortiVPNTunnel(self.config)
        else:
            print("Unsupported tunnel type")
            sys.exit(1)

        # Cleanup nameservers and routes from previous runs
        self.unset_nameservers()
        self.unset_routes()

        tunnel.start_tunnel(otp=otp)

        # Add routes and names etc
        self.set_routes(tunnel.interface)
        self.set_nameservers()

        # Set colors to terminal
        print("\033]6;1;bg;green;brightness;220\a")
        print("\033]6;1;bg;blue;brightness;0\a")
        print("\033]6;1;bg;red;brightness;0\a")

        try:
            while tunnel.check_tunnel():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Got ctrl+c, stopping")
            tunnel.stop_tunnel()
        logger.info("Tunnel is dead")
        self.unset_nameservers()
        self.unset_routes()

        # Unset colors from terminal
        print("\033]6;1;bg;green;brightness;0\a")
        print("\033]6;1;bg;blue;brightness;0\a")
        print("\033]6;1;bg;red;brightness;220\a")
        print("\033]6;1;bg;*;default\a")


def main():
    name = None
    otp = None
    if len(sys.argv) < 2:
        print("Usage %s name [otp]" % sys.argv[0])
        sys.exit(1)
    if len(sys.argv) >= 2:
        name = sys.argv[1]
    if len(sys.argv) >= 3:
        otp = sys.argv[2]
    uid = os.getuid()
    if uid != 0:
        print("Process requires root privileges")
        sys.exit(1)
    tunnelit = TunnelIT(name)
    tunnelit.run(otp)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
