-- Bait schema for the MySQL decoy. Every row is invented; nothing here is real data.
CREATE DATABASE IF NOT EXISTS corp_hr;
USE corp_hr;

CREATE TABLE IF NOT EXISTS customers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  full_name VARCHAR(80), email VARCHAR(120), phone VARCHAR(24),
  address VARCHAR(160), kyc_status VARCHAR(16), created_at DATE
);

CREATE TABLE IF NOT EXISTS payments (
  id INT PRIMARY KEY AUTO_INCREMENT,
  customer_id INT, card_last4 CHAR(4), amount_cents INT,
  currency CHAR(3), status VARCHAR(16), created_at DATETIME,
  FOREIGN KEY (customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS credentials (
  service VARCHAR(40) PRIMARY KEY,
  username VARCHAR(40), password VARCHAR(64), note VARCHAR(120)
);

INSERT IGNORE INTO customers (id, full_name, email, phone, address, kyc_status, created_at) VALUES
 (1,'Aarav Kumar','aarav.kumar@northwind.example','+91 98450 11223','14 MG Road, Bengaluru','VERIFIED','2023-02-11'),
 (2,'Sneha Rao','sneha.rao@northwind.example','+91 98450 44556','22 Residency Rd, Bengaluru','VERIFIED','2023-03-04'),
 (3,'Marcus Feld','m.feld@northwind.example','+49 30 5550 1188','Torstrasse 9, Berlin','PENDING','2023-05-19'),
 (4,'Lucia Ortega','l.ortega@northwind.example','+34 91 555 0192','Calle Mayor 41, Madrid','VERIFIED','2023-06-27'),
 (5,'Kenji Sato','k.sato@northwind.example','+81 3 5550 7731','2-1 Marunouchi, Tokyo','REVIEW','2023-08-02');

INSERT IGNORE INTO payments (id, customer_id, card_last4, amount_cents, currency, status, created_at) VALUES
 (1,1,'4242',189900,'INR','SETTLED','2024-01-08 10:14:00'),
 (2,2,'1881',42000,'INR','SETTLED','2024-01-09 16:02:00'),
 (3,3,'9004',315000,'EUR','REFUNDED','2024-01-11 09:45:00'),
 (4,4,'7311',89900,'EUR','SETTLED','2024-01-12 12:31:00'),
 (5,5,'5502',128000,'JPY','FAILED','2024-01-14 20:08:00');

INSERT IGNORE INTO credentials (service, username, password, note) VALUES
 ('vpn','vpn_admin','Vp#n2024!rotate','rotates quarterly'),
 ('backup','svc_backup','Sup3rS3cret!2024','used by the nightly job'),
 ('payroll','hr_admin','Payr0ll!2024','SSO not enabled'),
 ('staging-db','deploy','D3ploy!staging','shared with contractors');

CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'app_secret_2024';
GRANT SELECT ON corp_hr.* TO 'app'@'%';
FLUSH PRIVILEGES;
