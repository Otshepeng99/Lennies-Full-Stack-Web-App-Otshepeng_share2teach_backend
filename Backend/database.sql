-- Create USER table with user_id as INT
CREATE TABLE public."USER" (
    user_id SERIAL PRIMARY KEY,
    user_Fname VARCHAR(255) NOT NULL,
    user_Lname VARCHAR(255) NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    userpassword VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'moderator', 'educator', 'open-access'))
);

-- Create FILE table with uploaded_by as INT
CREATE TABLE public."FILE" (
    file_id SERIAL PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    subject VARCHAR(255),
    grade VARCHAR(50),
    keywords TEXT[],
    tags TEXT[],
    rating DECIMAL(2, 1),
    storage_path TEXT NOT NULL,
    uploaded_by INT REFERENCES public."USER"(user_id),
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create RATING table with user_id as INT
CREATE TABLE public."RATING" (
    rating_id SERIAL PRIMARY KEY,
    file_id INT REFERENCES public."FILE"(file_id) ON DELETE CASCADE,
    user_id INT REFERENCES public."USER"(user_id) ON DELETE CASCADE,
    rating DECIMAL(2, 1) NOT NULL CHECK (rating >= 1 AND rating <= 5),
    UNIQUE(file_id, user_id)
);

-- Create FAQ table
CREATE TABLE public."FAQ" (
    faq_id SERIAL PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT,
    created_by INT REFERENCES public."USER"(user_id) ON DELETE SET NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'answered', 'rejected')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create a function to update 'updated_at' timestamp on row modification
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

-- Create a trigger that invokes the above function before any UPDATE on 'FAQ'
CREATE TRIGGER update_faq_updated_at
BEFORE UPDATE ON public."FAQ"
FOR EACH ROW
EXECUTE PROCEDURE update_updated_at_column();