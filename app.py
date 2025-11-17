import streamlit as st
from db import init_db, get_conn
from auth import authenticate, hash_password, can
from security import mask_name, mask_contact, encrypt_value, decrypt_value
from logs import write_log, fetch_logs
import pandas as pd
import datetime
import sqlite3
import io
import shutil
from pathlib import Path
import pytz

init_db()

tz = pytz.timezone('Asia/Karachi')

if "app_start" not in st.session_state:
    st.session_state["app_start"] = datetime.datetime.now(datetime.UTC)

if "user" not in st.session_state:
    st.set_page_config(page_title="Hospital Dashboard — Login")
    st.title("Hospital Dashboard — Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        try:
            user = authenticate(username, password)
            if user:
                st.session_state.user = user
                write_log(user["user_id"], user["role"], "login", f"{username} logged in")
            else:
                st.error("Invalid credentials")
        except Exception as e:
            try:
                write_log(None, "unknown", "login_error", str(e))
            except Exception:
                pass
            st.error("Login failed (unexpected error).")
        st.rerun()
else:
    user = st.session_state.user
    st.set_page_config(page_title="Hospital Dashboard")
    st.sidebar.write(f"Logged in as: **{user['username']}**  \nRole: **{user['role']}**")
    page = st.sidebar.radio("Page", ["Patients","Add / Edit Patient","Anonymize","Audit Logs","Export & Backup","Logout"])
    
    if page == "Patients":
        st.header("Patients")
        try:
            conn = get_conn()
            df = pd.read_sql_query("SELECT * FROM patients ORDER BY date_added DESC", conn)
            conn.close()
            if df.empty:
                st.info("No patient records yet.")
            else:
                if can(user["role"], "view_raw"):
                    st.subheader("Raw patient data (Admin)")
                    st.dataframe(df)
                    write_log(user["user_id"], user["role"], "view_raw_patients", "Viewed raw patient table")
                elif can(user["role"], "view_anon"):
                    st.subheader("Anonymized patient data")
                    df_view = df.copy()
                    df_view["display_name"] = df_view.apply(
                        lambda r: r["anonymized_name"] if r["anonymized_name"] else mask_name(r["name"], r["patient_id"]),
                        axis=1
                    )
                    df_view["display_contact"] = df_view.apply(
                        lambda r: r["anonymized_contact"] if r["anonymized_contact"] else mask_contact(r["contact"]),
                        axis=1
                    )
                    st.dataframe(df_view[["patient_id","display_name","display_contact","diagnosis","date_added"]])
                    write_log(user["user_id"], user["role"], "view_anon_patients", "Viewed anonymized patients")
                else:
                    st.info("You do not have permission to view patient data.")
        except sqlite3.Error as e:
            write_log(user["user_id"], user["role"], "db_error", f"Patients read failed: {str(e)}")
            st.error("Failed to load patients (database error).")
        except Exception as e:
            write_log(user["user_id"], user["role"], "error", f"Patients read unexpected: {str(e)}")
            st.error("Unexpected error while loading patients.")

    elif page == "Add / Edit Patient":
        st.header("Add / Edit Patient")
        can_edit = can(user["role"], "edit")
        if not can_edit:
            st.info("You do not have permission to add or edit patient records.")
        else:
            try:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("SELECT patient_id, date_added FROM patients ORDER BY date_added DESC")
                patients = cur.fetchall()
                patient_options = {row["patient_id"]: row["patient_id"] for row in patients}
                edit_choice = st.selectbox("Select patient to edit (or choose Add new)", ["Add new"] + list(map(str, patient_options.keys())))
                
                if edit_choice == "Add new":
                    st.subheader("Add new patient")
                    name = st.text_input("Name")
                    contact = st.text_input("Contact")
                    diagnosis = st.text_area("Diagnosis / Notes")
                    if st.button("Save New Patient"):
                        if not name.strip():
                            st.error("Name is required.")
                        else:
                            try:
                                now = datetime.datetime.now(datetime.UTC).isoformat()
                                cur.execute(
                                    "INSERT INTO patients (name, contact, diagnosis, date_added) VALUES (?,?,?,?)",
                                    (name.strip(), contact.strip(), diagnosis.strip(), now)
                                )
                                conn.commit()
                                pid = cur.lastrowid
                                write_log(user["user_id"], user["role"], "add_patient", f"Added patient_id={pid}")
                                st.success(f"Patient added (id={pid}).")
                            except sqlite3.Error as e:
                                write_log(user["user_id"], user["role"], "db_error", f"Add patient failed: {str(e)}")
                                st.error("Failed to add patient (DB error).")
                else:
                    pid = int(edit_choice)
                    cur.execute("SELECT * FROM patients WHERE patient_id = ?", (pid,))
                    row = cur.fetchone()
                    if not row:
                        st.error("Selected patient not found.")
                    else:
                        st.subheader(f"Edit patient id={pid}")
                        if can(user["role"], "view_raw"):
                            name_val = row["name"]
                            contact_val = row["contact"]
                        else:
                            name_val = ""
                            contact_val = ""
                        st.info(f"Anonymized name: {row['anonymized_name'] or mask_name(row['name'], row['patient_id'])}")
                        st.info(f"Anonymized contact: {row['anonymized_contact'] or mask_contact(row['contact'])}")
                        name = st.text_input("Name (raw viewable only to Admin)", value=name_val)
                        contact = st.text_input("Contact (raw viewable only to Admin)", value=contact_val)
                        diagnosis = st.text_area("Diagnosis / Notes", value=row["diagnosis"] or "")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.button("Save Changes"):
                                try:
                                    if can(user["role"], "view_raw") and not name.strip():
                                        st.error("Name cannot be empty.")
                                    else:
                                        cur.execute(
                                            "UPDATE patients SET name=?, contact=?, diagnosis=? WHERE patient_id=?",
                                            (name.strip() if name is not None else row["name"],
                                             contact.strip() if contact is not None else row["contact"],
                                             diagnosis.strip(), pid)
                                        )
                                        conn.commit()
                                        write_log(user["user_id"], user["role"], "update_patient", f"Updated patient_id={pid}")
                                        st.success("Changes saved.")
                                except sqlite3.Error as e:
                                    write_log(user["user_id"], user["role"], "db_error", f"Update patient failed: {str(e)}")
                                    st.error("Failed to save changes (DB error).")
                        with col2:
                            if st.button("Delete Patient"):
                                if user["role"] != "admin":
                                    st.error("Only admin can delete records.")
                                else:
                                    try:
                                        cur.execute("DELETE FROM patients WHERE patient_id = ?", (pid,))
                                        conn.commit()
                                        write_log(user["user_id"], user["role"], "delete_patient", f"Deleted patient_id={pid}")
                                        st.success("Patient deleted.")
                                    except sqlite3.Error as e:
                                        write_log(user["user_id"], user["role"], "db_error", f"Delete patient failed: {str(e)}")
                                        st.error("Failed to delete patient (DB error).")
                conn.close()
            except sqlite3.Error as e:
                write_log(user["user_id"], user["role"], "db_error", f"Add/Edit page DB error: {str(e)}")
                st.error("Database error on Add/Edit page.")
            except Exception as e:
                write_log(user["user_id"], user["role"], "error", f"Add/Edit unexpected: {str(e)}")
                st.error("Unexpected error on Add/Edit page.")

    elif page == "Anonymize":
        st.header("Anonymize / Pseudonymize Data (Admin only)")
        if user["role"] != "admin":
            st.info("Only Admin may anonymize data.")
        else:
            st.write("Anonymization will fill `anonymized_name` and `anonymized_contact` for all patients.")
            st.write("Admin can also optionally encrypt raw name/contact into extra columns (if not present).")
            try:
                conn = get_conn()
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM patients WHERE anonymized_name IS NULL OR anonymized_name = ''")
                to_anonymize = cur.fetchone()[0]
                st.write(f"Records needing anonymization: {to_anonymize}")
                if st.button("Anonymize all records now"):
                    try:
                        cur.execute("SELECT patient_id, name, contact FROM patients")
                        rows = cur.fetchall()
                        for r in rows:
                            pid = r["patient_id"]
                            name = r["name"] or ""
                            contact = r["contact"] or ""
                            anon_name = mask_name(name, pid)
                            anon_contact = mask_contact(contact)
                            cur.execute(
                                "UPDATE patients SET anonymized_name=?, anonymized_contact=? WHERE patient_id=?",
                                (anon_name, anon_contact, pid)
                            )
                        conn.commit()
                        write_log(user["user_id"], user["role"], "anonymize", f"Anonymized {len(rows)} records")
                        st.success(f"Anonymized {len(rows)} records.")
                    except sqlite3.Error as e:
                        write_log(user["user_id"], user["role"], "db_error", f"Anonymize failed: {str(e)}")
                        st.error("Anonymization failed (DB error).")
                st.markdown("---")
                if st.checkbox("Also encrypt raw data into enc_name/enc_contact columns (reversible, bonus)"):
                    if st.button("Encrypt raw fields into enc_name/enc_contact"):
                        try:
                            try:
                                cur.execute("ALTER TABLE patients ADD COLUMN enc_name BLOB")
                                cur.execute("ALTER TABLE patients ADD COLUMN enc_contact BLOB")
                                conn.commit()
                            except sqlite3.Error:
                                pass
                            cur.execute("SELECT patient_id, name, contact FROM patients")
                            rows = cur.fetchall()
                            for r in rows:
                                pid = r["patient_id"]
                                name = r["name"] or ""
                                contact = r["contact"] or ""
                                encn = encrypt_value(name) if name else None
                                encc = encrypt_value(contact) if contact else None
                                cur.execute("UPDATE patients SET enc_name=?, enc_contact=? WHERE patient_id=?",
                                            (encn, encc, pid))
                            conn.commit()
                            write_log(user["user_id"], user["role"], "encrypt_raw", "Encrypted raw name/contact to enc_name/enc_contact")
                            st.success("Encrypted raw fields and stored in enc_name/enc_contact.")
                        except Exception as e:
                            write_log(user["user_id"], user["role"], "error", f"Encrypt raw failed: {str(e)}")
                            st.error("Failed to encrypt raw fields.")
                conn.close()
            except sqlite3.Error as e:
                write_log(user["user_id"], user["role"], "db_error", f"Anonymize page DB error: {str(e)}")
                st.error("Database error on anonymize page.")
            except Exception as e:
                write_log(user["user_id"], user["role"], "error", f"Anonymize page unexpected: {str(e)}")
                st.error("Unexpected error on anonymize page.")

    elif page == "Audit Logs":
        st.header("Integrity Audit Log (Admin only)")
        if user["role"] != "admin":
            st.info("Only Admin may view the audit logs.")
        else:
            try:
                logs = fetch_logs(limit=1000)
                if not logs:
                    st.info("No logs yet.")
                else:
                    df_logs = pd.DataFrame([dict(r) for r in logs])
                    st.sidebar.subheader("Log Filters")
                    roles = ["all"] + sorted(df_logs['role'].dropna().unique().tolist())
                    actions = ["all"] + sorted(df_logs['action'].dropna().unique().tolist())
                    sel_role = st.sidebar.selectbox("Role", roles)
                    sel_action = st.sidebar.selectbox("Action", actions)
                    start_date = st.sidebar.date_input("From date", value=datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(days=30))
                    end_date = st.sidebar.date_input("To date", value=datetime.datetime.now(datetime.UTC).date())
                    
                    df_filter = df_logs.copy()
                    df_filter["timestamp_dt"] = pd.to_datetime(df_filter["timestamp"], errors="coerce")
                    df_filter = df_filter[(df_filter["timestamp_dt"].dt.date >= start_date) & (df_filter["timestamp_dt"].dt.date <= end_date)]
                    if sel_role != "all":
                        df_filter = df_filter[df_filter["role"] == sel_role]
                    if sel_action != "all":
                        df_filter = df_filter[df_filter["action"] == sel_action]
                    st.dataframe(df_filter.sort_values("timestamp_dt", ascending=False).drop(columns=["timestamp_dt"]))
                    write_log(user["user_id"], user["role"], "view_logs", f"Viewed logs with filters role={sel_role} action={sel_action}")
                    
                    csv = df_filter.to_csv(index=False).encode('utf-8')
                    st.download_button("Download filtered logs (CSV)", csv, file_name="audit_logs.csv", mime="text/csv")
            except sqlite3.Error as e:
                write_log(user["user_id"], user["role"], "db_error", f"Audit logs read failed: {str(e)}")
                st.error("Failed to load audit logs (DB error).")
            except Exception as e:
                write_log(user["user_id"], user["role"], "error", f"Audit logs unexpected: {str(e)}")
                st.error("Unexpected error while loading logs.")
    
    elif page == "Export & Backup":
        st.header("Export & Backup")
        st.write("Download CSV exports or a backup copy of the SQLite DB file.")

        try:
            conn = get_conn()
            patients_df = pd.read_sql_query("SELECT * FROM patients", conn)
            logs_df = pd.read_sql_query("SELECT * FROM logs", conn)
            conn.close()
        except sqlite3.Error as e:
            write_log(user["user_id"], user["role"], "db_error", f"Export page DB error: {str(e)}")
            st.error("Database error on export page.")
            st.stop()
        except Exception as e:
            write_log(user["user_id"], user["role"], "error", f"Export page unexpected: {str(e)}")
            st.error("Unexpected error on export page.")
            st.stop()

        st.subheader("Patients export")
        st.write(f"Total patient records: {len(patients_df)}")
        if st.button("Prepare patients CSV"):
            try:
                csv_pat = patients_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download patients CSV",
                    data=csv_pat,
                    file_name="patients_export.csv",
                    mime="text/csv",
                    key="patients_csv_download"
                )
                write_log(user["user_id"], user["role"], "export_csv", "Prepared patients CSV for download")
            except Exception as e:
                write_log(user["user_id"], user["role"], "error", f"Patients CSV export failed: {str(e)}")
                st.error("Failed to prepare patients CSV.")

        st.subheader("Logs export")
        if st.button("Prepare logs CSV"):
            try:
                csv_logs = logs_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download logs CSV",
                    data=csv_logs,
                    file_name="logs_export.csv",
                    mime="text/csv",
                    key="logs_csv_download"
                )
                write_log(user["user_id"], user["role"], "export_csv", "Prepared logs CSV for download")
            except Exception as e:
                write_log(user["user_id"], user["role"], "error", f"Logs CSV export failed: {str(e)}")
                st.error("Failed to prepare logs CSV.")

        st.subheader("Database backup (SQLite)")
        db_path = Path("hospital.db")
        if db_path.exists():
            if st.button("Prepare DB backup"):
                try:
                    with open(db_path, "rb") as f:
                        db_bytes = f.read()
                    st.download_button(
                        label="Download hospital.db (backup)",
                        data=db_bytes,
                        file_name=f"hospital_backup_{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d_%H%M%S')}.db",
                        mime="application/octet-stream",
                        key="db_backup_download"
                    )
                    write_log(user["user_id"], user["role"], "backup", "Prepared DB backup for download")
                except Exception as e:
                    write_log(user["user_id"], user["role"], "error", f"DB backup download failed: {str(e)}")
                    st.error("Failed to prepare DB backup.")

            if st.button("Create server-side timestamped backup file (copy)"):
                backup_name = f"hospital_backup_{datetime.datetime.now(datetime.UTC).strftime('%Y%m%d_%H%M%S')}.db"
                try:
                    shutil.copy(db_path, backup_name)
                    write_log(user["user_id"], user["role"], "backup", f"Created server-side backup file {backup_name}")
                    st.success(f"Backup created as {backup_name}")
                except Exception as e:
                    write_log(user["user_id"], user["role"], "error", f"Server-side backup failed: {str(e)}")
                    st.error("Failed to create server-side backup copy.")
        else:
            st.error("Database file not found.")

    
    elif page == "Logout":
        if st.button("Logout"):
            try:
                write_log(user["user_id"], user["role"], "logout", f"{user['username']} logged out")
            except Exception:
                pass
            del st.session_state.user
            st.rerun()
    
    st.markdown("---")
    try:
        uptime = datetime.datetime.now(datetime.UTC) - st.session_state["app_start"]
        # Format uptime
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        footer = f"Uptime: {hours}h {minutes}m {seconds}s  —  Last sync: {datetime.datetime.now(datetime.UTC).isoformat()} UTC"
        st.caption(footer)
    except Exception:
        st.caption("Uptime information unavailable.")
