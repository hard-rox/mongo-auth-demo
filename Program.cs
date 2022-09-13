using System.Text;
using AspNetCore.Identity.Mongo;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MongoAuth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddIdentityMongoDbProvider<ApplicationUser, ApplicationRole>(identity =>
{
    identity.Password.RequireNonAlphanumeric = false;
    identity.Password.RequiredUniqueChars = 0;
    identity.Password.RequireUppercase = false;
    identity.Password.RequireLowercase = false;
    identity.Password.RequireDigit = false;
    identity.Password.RequireLowercase = false;
    identity.Password.RequireUppercase = false;
}, mongo =>
{
    // mongo.ConnectionString = @"mongodb+srv://ishaf:shafiul@cluster0.aecb7.mongodb.net/roxtest?retryWrites=true&w=majority";
    mongo.ConnectionString = @"mongodb://root:123456Aa@localhost:27017/mongo_auth?authSource=admin";
})
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = "aud",
        ValidIssuer = "localhost",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("6FDAFD81C19920ED01042F440C5A406146B10F09CAD8A0EF721A453E714F574B"))
    };
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(opt =>
{
    opt.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "Mongo Auth"
    });
    opt.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        In = ParameterLocation.Header,
        Description = "Provide Token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    opt.AddSecurityRequirement(new OpenApiSecurityRequirement(){
        {
            new OpenApiSecurityScheme(){
                Reference = new OpenApiReference(){
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[]{}
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
