# -*- coding: utf-8 -*-
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

import unittest
import time
import re
import sys

github_account = "amoreidp"
github_passwd = ""
AMOREIDP_CODES = ["7c06c-f946c", "78956-1369b", "8b41f-61913", "2742f-73930"]
AMOREIDP_PASSWD = "vivA8v8Lz45Nx5J"


def add_device(device_code):
    options = Options()
    options.headless = True
    driver = webdriver.Firefox(executable_path="/opt/geckodriver", options=options)
    driver.get("https://github.com/login/device")
    driver.find_element_by_id("login_field").send_keys(github_account)
    driver.find_element_by_id("password").send_keys(AMOREIDP_PASSWD)
    driver.find_element_by_name("commit").click()
    driver.get_screenshot_as_file("/var/log/httpd/device1.png")
    driver.find_element_by_link_text("Use a recovery code or request a reset").click()
    driver.get_screenshot_as_file("/var/log/httpd/device2.png")
    driver.find_element_by_id('recovery_code').send_keys('1c1fc-e0e50')
    driver.get_screenshot_as_file("/var/log/httpd/device3.png")
    xpath = '//*[@id="login"]/form/div[3]/div[2]/button'
    # full_xpath = '/html/body/div[3]/main/div/div/form/div[3]/div[2]/button'
    report1 = driver.find_element_by_xpath(xpath)
    report1.click()
    driver.get_screenshot_as_file("/var/log/httpd/device3_1.png")
    driver.get("https://github.com/login/device")
    driver.get_screenshot_as_file("/var/log/httpd/device3_2.png")
    driver.find_element_by_name('user-code-0').send_keys(device_code[0])
    driver.get_screenshot_as_file("/var/log/httpd/device4.png")
    driver.find_element_by_name('user-code-1').send_keys(device_code[1])
    driver.find_element_by_name('user-code-2').send_keys(device_code[2])
    driver.find_element_by_name('user-code-3').send_keys(device_code[3])
    driver.find_element_by_name('user-code-5').send_keys(device_code[4])
    driver.find_element_by_name('user-code-6').send_keys(device_code[5])
    driver.find_element_by_name('user-code-7').send_keys(device_code[6])
    driver.find_element_by_name('user-code-8').send_keys(device_code[7])
    driver.get_screenshot_as_file("/var/log/httpd/device5.png")
    driver.find_element_by_name("commit").click()
    driver.get_screenshot_as_file("/var/log/httpd/device6.png")
    driver.get_screenshot_as_file("/var/log/httpd/device7.png")
    driver.find_element_by_name("authorize").click()
    driver.get_screenshot_as_file("/var/log/httpd/device8.png")


class GithubLogin(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Firefox()
        self.driver.implicitly_wait(30)
        self.base_url = "https://github.com/"
        self.verificationErrors = []
        self.accept_next_alert = True

    def test_github_login(self, device_code):
        driver = self.driver
        try:
            driver.get(self.base_url + "/login")
        finally:
            driver.find_element_by_id("login_field").clear()
        driver.find_element_by_id("login_field").send_keys(github_account)
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys(github_passwd)
        driver.find_element_by_name("commit").click()
        driver.find_element_by_link_text("Repositories").click()
        driver.navigate().to("editURL")
        driver.find_element_by_id('user-code-7').send_keys(device_code[6])
        driver.find_element_by_link_text("Company").click()
        xpath = '//*[@id="login"]/form/div[3]/div[2]/button'
        full_xpath = '/html/body/div[3]/main/div/div/form/div[3]/div[2]/button'
        report1 = driver.find_element_by_xpath(xpath)
        report1.click()
        error = "Recovery code authentication failed."


    def is_element_present(self, how, what):
        try:
            self.driver.find_element(by=how, value=what)
        except NoSuchElementException as e:
            return False
        return True

    def is_alert_present(self):
        try:
            self.driver.switch_to_alert()
        except NoAlertPresentException as e:
            return False
        return True

    def close_alert_and_get_its_text(self):
        try:
            alert = self.driver.switch_to_alert()
            alert_text = alert.text
            if self.accept_next_alert:
                alert.accept()
            else:
                alert.dismiss()
            return alert_text
        finally:
            self.accept_next_alert = True

    def devicelogin(self):
        url = "https://github.com/login/device"


    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)


if __name__ == "__main__":
    unittest.main()
