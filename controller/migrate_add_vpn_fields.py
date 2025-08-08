#!/usr/bin/env python3
"""
Migration script to add VPN fields to scan_jobs table
"""

import sqlite3
import os

def migrate_database():
    """Add VPN fields to scan_jobs table"""
    
    # Database path - check multiple locations
    possible_paths = [
        os.getenv("DATABASE_PATH", "scan_results.db"),
        "/data/scan_results.db",  # Container path
        "scan_results.db",        # Local path
        "./scan_results.db"       # Current directory
    ]
    
    db_path = None
    for path in possible_paths:
        if os.path.exists(path):
            db_path = path
            break
    
    if not db_path:
        # Use container path if running in container
        if os.path.exists("/data"):
            db_path = "/data/scan_results.db"
        else:
            db_path = "scan_results.db"
        print(f"Database not found, will create at: {db_path}")
    else:
        print(f"Using existing database: {db_path}")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if vpn_profile column already exists
        cursor.execute("PRAGMA table_info(scan_jobs)")
        columns = [column[1] for column in cursor.fetchall()]
        
        vpn_fields = [
            ("vpn_profile", "TEXT"),
            ("vpn_country", "TEXT"), 
            ("vpn_hostname", "TEXT"),
            ("vpn_assignment", "TEXT")  # JSON as TEXT in SQLite
        ]
        
        for field_name, field_type in vpn_fields:
            if field_name not in columns:
                print(f"Adding column: {field_name}")
                cursor.execute(f"ALTER TABLE scan_jobs ADD COLUMN {field_name} {field_type}")
            else:
                print(f"Column {field_name} already exists")
        
        conn.commit()
        print("✅ Database migration completed successfully")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
