CREATE DATABASE IF NOT EXISTS `secured_login` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;

USE `secured_login`;

CREATE TABLE IF NOT EXISTS `accounts` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
	`username` varchar(100) NOT NULL,
	`password` varchar(255) NOT NULL,
	`email` varchar(100) NOT NULL,
    `password_hist1` varchar(255) NOT NULL DEFAULT '',
    `password_hist2` varchar(255) NOT NULL DEFAULT '',
    `password_hist3` varchar(255) NOT NULL DEFAULT '',
    `curr_salt` varchar(255) NOT NULL DEFAULT '',
    `salt_hist1` varchar(255) NOT NULL DEFAULT '',
    `salt_hist2` varchar(255) NOT NULL DEFAULT '',
    `salt_hist3` varchar(255) NOT NULL DEFAULT '',
    `login_attempts` int(50) NOT NULL DEFAULT 0,
    `reset_code` varchar(255) NOT NULL DEFAULT '',
	PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `customers` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
	`cust_name` varchar(500) NOT NULL,
	`cust_email` varchar(500) NOT NULL,
    `registered_by` varchar(100) NOT NULL,
	PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

INSERT INTO accounts VALUES( 1, 'admin', 'password','naticoding@gmail.com', 'none', 'none','none', 'none', 'none', 'none', 'none', 0, 'none' );


SELECT * from accounts;