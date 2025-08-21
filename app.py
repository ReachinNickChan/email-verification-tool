import os
import csv
from flask import Flask, request, render_template, send_file, after_this_request
from werkzeug.utils import secure_filename
from email_verifier import check_syntax, check_mx_records, check_smtp

# Initialize the Flask app
app = Flask(__name__)
# Set a folder for temporary file uploads
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET'])
def index():
    """Renders the main upload page."""
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_emails():
    """Handles the file upload and verification process."""
    if 'email_file' not in request.files:
        return "No file part", 400
    file = request.files['email_file']
    if file.filename == '':
        return "No selected file", 400

    if file and file.filename.endswith('.csv'):
        # Save the uploaded file securely
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)

        # Prepare the output file path
        output_filename = f"results_{filename}"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        results = []
        try:
            with open(input_path, mode='r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                if 'Email' not in reader.fieldnames:
                    return "Error: Input CSV must contain an 'Email' column.", 400
                
                # --- This is the verification logic from your original main.py ---
                for row in reader:
                    email = row['Email'].strip()
                    syntax_valid = check_syntax(email)
                    domain_has_mx = False
                    mailbox_exists = "Unverifiable"
                    
                    if syntax_valid:
                        domain = email.split('@')[1]
                        mx_records = check_mx_records(domain)
                        if mx_records:
                            domain_has_mx = True
                            mailbox_exists = check_smtp(email, mx_records)

                        if domain_has_mx and mailbox_exists == "Exists":
                            overall_status = "Valid"
                        else:
                            overall_status = "Risky / Invalid"
                    else:
                        overall_status = "Invalid Syntax"

                    results.append({
                        'Email': email,
                        'SyntaxValid': "Valid" if syntax_valid else "Invalid",
                        'DomainHasMX': "True" if domain_has_mx else "False",
                        'MailboxExists': mailbox_exists,
                        'OverallStatus': overall_status
                    })
        except Exception as e:
            return f"An error occurred: {e}", 500
        
        # Write results to the output CSV
        with open(output_path, mode='w', newline='', encoding='utf-8') as outfile:
            fieldnames = ['Email', 'SyntaxValid', 'DomainHasMX', 'MailboxExists', 'OverallStatus']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        # Clean up the files after the request is finished
        @after_this_request
        def cleanup(response):
            try:
                os.remove(input_path)
                os.remove(output_path)
            except Exception as error:
                app.logger.error("Error removing or cleaning up file: %s", error)
            return response

        # Send the results file to the user for download
        return send_file(output_path, as_attachment=True, download_name=output_filename)

    return "Invalid file type. Please upload a CSV.", 400

if __name__ == '__main__':
    app.run(debug=True)